//go:build !linux

package lanclient

func loadPackageLocal(Material) (packageLocal, error) { return packageLocal{}, errPackageDisabled }
