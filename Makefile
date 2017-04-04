bin/dnsdog: *.go
	docker build -t remind101/dnsdog .
	docker cp $(shell docker create remind101/dnsdog):/go/bin/dnsdog bin/
