package main

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

func statusIcon(base []byte, state snapshot, settingUp bool) []byte {
	if (state.portAvailable() || state.Remote) && !state.Locked && !state.NeedsDeviceApproval && !settingUp {
		return base
	}
	icon, err := png.Decode(bytes.NewReader(base))
	if err != nil {
		return base
	}
	badged := image.NewNRGBA(icon.Bounds())
	draw.Draw(badged, badged.Bounds(), icon, image.Point{}, draw.Src)
	ink := color.NRGBA{R: 31, G: 26, B: 10, A: 255}
	gold := color.NRGBA{R: 255, G: 190, B: 11, A: 255}
	for y := 30; y < 64; y++ {
		for x := 30; x < 64; x++ {
			dx, dy := x-47, y-47
			switch distance := dx*dx + dy*dy; {
			case distance <= 15*15:
				badged.SetNRGBA(x, y, gold)
			case distance <= 17*17:
				badged.SetNRGBA(x, y, ink)
			}
		}
	}
	fill := func(x0, y0, x1, y1 int) {
		draw.Draw(badged, image.Rect(x0, y0, x1, y1), image.NewUniform(ink), image.Point{}, draw.Src)
	}
	if state.Locked && !settingUp {
		fill(40, 45, 55, 56)
		fill(42, 40, 45, 46)
		fill(50, 40, 53, 46)
		fill(44, 38, 51, 41)
	} else {
		fill(45, 37, 50, 49)
		fill(45, 52, 50, 57)
	}
	var output bytes.Buffer
	if png.Encode(&output, badged) != nil {
		return base
	}
	return output.Bytes()
}
