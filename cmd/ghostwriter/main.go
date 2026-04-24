// GHOSTWRITER — Behavioral Attacker Intelligence Framework
//
// "Same attacker. Different IP. Still caught."
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com
// GitHub: https://github.com/Dexel-Software-Solutions
package main

import (
	"fmt"
	"os"

	"github.com/Dexel-Software-Solutions/ghostwriter/cmd/ghostwriter/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  Error: %v\n\n", err)
		os.Exit(1)
	}
}
