// Planted defect for the dupl self-test (#200). Its own module, so ./... of
// the main module never sees it. Expected: dupl reports the two functions
// below as duplicates of each other (well over the 150-token threshold).
package main

import "fmt"

func sumEven(values []int) (int, []string) {
	total := 0
	var notes []string
	for i, v := range values {
		if v%2 == 0 {
			total += v
			notes = append(notes, fmt.Sprintf("index %d: even value %d, running total %d", i, v, total))
		} else {
			notes = append(notes, fmt.Sprintf("index %d: skipped odd value %d", i, v))
		}
	}
	if total > 100 {
		notes = append(notes, fmt.Sprintf("total %d is above the limit", total))
	}
	counts := map[string]int{}
	for _, n := range notes {
		if len(n) > 20 {
			counts["long"]++
		} else if len(n) > 10 {
			counts["medium"]++
		} else {
			counts["short"]++
		}
	}
	for k, c := range counts {
		if c > 1 {
			notes = append(notes, fmt.Sprintf("%s notes: %d", k, c))
		}
	}
	for i := range notes {
		for j := i + 1; j < len(notes); j++ {
			if notes[i] == notes[j] {
				notes[j] = fmt.Sprintf("%s (repeat %d)", notes[j], j-i)
			}
		}
	}
	return total, notes
}

func sumOdd(values []int) (int, []string) {
	total := 0
	var notes []string
	for i, v := range values {
		if v%2 != 0 {
			total += v
			notes = append(notes, fmt.Sprintf("index %d: odd value %d, running total %d", i, v, total))
		} else {
			notes = append(notes, fmt.Sprintf("index %d: skipped even value %d", i, v))
		}
	}
	if total > 100 {
		notes = append(notes, fmt.Sprintf("total %d is above the limit", total))
	}
	counts := map[string]int{}
	for _, n := range notes {
		if len(n) > 20 {
			counts["long"]++
		} else if len(n) > 10 {
			counts["medium"]++
		} else {
			counts["short"]++
		}
	}
	for k, c := range counts {
		if c > 1 {
			notes = append(notes, fmt.Sprintf("%s notes: %d", k, c))
		}
	}
	for i := range notes {
		for j := i + 1; j < len(notes); j++ {
			if notes[i] == notes[j] {
				notes[j] = fmt.Sprintf("%s (repeat %d)", notes[j], j-i)
			}
		}
	}
	return total, notes
}

func main() {
	fmt.Println(sumEven([]int{1, 2, 3}))
	fmt.Println(sumOdd([]int{1, 2, 3}))
}
