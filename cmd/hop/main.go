// Command hop is the HopKey command-line client.
package main

import (
	"fmt"

	"github.com/dalyem/hopkey/internal/version"
)

func main() {
	fmt.Println("hop", version.Version)
}
