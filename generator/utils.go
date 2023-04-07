package generator

func F(n int) int {
	return (n - 1) / 3
}

func Q(n int) int {
	return n - F(n)
}
