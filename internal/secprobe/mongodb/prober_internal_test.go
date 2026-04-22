package mongodb

import "testing"

func TestMongoURIFormatsIPv6Hosts(t *testing.T) {
	got := mongoURI("2001:db8::1", 27017)
	want := "mongodb://[2001:db8::1]:27017/?directConnection=true"
	if got != want {
		t.Fatalf("mongoURI() = %q, want %q", got, want)
	}
}
