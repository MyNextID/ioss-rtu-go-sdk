package utils

type Alias[K ~string] map[K]string

func (a Alias[K]) Get(key K) string {
	if a != nil {
		if val, ok := a[key]; ok {
			return val
		}
	}
	return string(key)
}
