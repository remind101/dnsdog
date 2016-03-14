bin/dnsdog: *.go
	docker build -t remind101/dnsdog .
	docker cp $(shell docker run -d remind101/dnsdog):/go/bin/dnsdog bin/
