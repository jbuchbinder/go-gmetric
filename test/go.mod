module github.com/jbuchbinder/go-gmetric/test

go 1.15

replace (
	github.com/jbuchbinder/go-gmetric => ../
	github.com/jbuchbinder/go-gmetric/gmetric => ../gmetric
)

require github.com/jbuchbinder/go-gmetric/gmetric v0.0.0-00010101000000-000000000000
