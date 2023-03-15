package main

import "math"

func F(n int) int {
	return int(math.Ceil(float64(n)/3)) - 1
}

func Q(n int) int {
	return F(n)*2 + 1
}
