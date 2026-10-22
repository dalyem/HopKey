// Command hop-server is the HopKey sync server.
package main

import (
	"fmt"

	"github.com/dalyem/hopkey/internal/version"
)

func main() {
	fmt.Println("hop-server", version.Version)
}
