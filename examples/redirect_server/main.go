package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	// 根路径先跳到 /login，用于验证第一跳是否被记录。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// /login 再跳到 /home，用于验证多级重定向链路。
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusMovedPermanently)
	})

	// 最终落地页返回一个普通 HTML 首页。
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "gomap-redirect-example")
		fmt.Fprint(w, "<html><head><title>redirect-demo</title></head><body>ok</body></html>")
	})

	addr := ":18080"
	log.Printf("redirect test server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
