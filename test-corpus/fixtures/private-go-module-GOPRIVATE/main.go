package main

import (
	"fmt"
	"net/http"

	greet "github.com/strands-agents/box-corpus-private"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, greet.Hello(r.URL.Query().Get("name")))
	})
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
