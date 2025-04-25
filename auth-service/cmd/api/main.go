package main

import (
    "log"
    "net/http"
)

func main() {
    mux := routes()
    log.Println("Starting authentication service on port 8081...")
    err := http.ListenAndServe(":8081", mux)
    if err != nil {
        log.Fatal(err)
    }
}
