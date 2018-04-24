package goutil

import (
	"reflect"
	"strconv"
	"strings"
)

// JoinInt concatenates integers in one string with defined separator
func JoinInt(array []int, sep string) string {
	var buf []string
	for _, v := range array {
		buf = append(buf, strconv.Itoa(v))
	}
	return strings.Join(buf, sep)
}

// MemberOfSlice checks if object is element of slice
func MemberOfSlice(element interface{}, slice interface{}) bool {
	var (
		eType = reflect.TypeOf(element)
		sType = reflect.TypeOf(slice)
		sVal  = reflect.ValueOf(slice)
	)

	if sType.Kind() != reflect.Slice {
		panic("Second argument is not a slice")
	}

	if eType != sType.Elem() {
		panic("First argument and slice elements have different types")
	}

	if !eType.Comparable() || !sType.Elem().Comparable() {
		panic("Type is not comparable")
	}

	for i := 0; i < sVal.Len(); i++ {
		if element == sVal.Index(i).Interface() {
			return true
		}
	}
	return false
}

// DiffSlices returns differense between two slices
func DiffSlices(one interface{}, two interface{}) (interface{}, interface{}) {
	var (
		oneType = reflect.TypeOf(one)
		twoType = reflect.TypeOf(two)

		old, new []interface{}
	)

	if oneType.Kind() != reflect.Slice || twoType.Kind() != reflect.Slice {
		panic("One of arguments is not a slice")
	}

	if oneType.Elem() != twoType.Elem() {
		panic("Slices' elements have different types")
	}

	for _, v := range one.([]interface{}) {
		if !MemberOfSlice(v, two) {
			old = append(old, v)
		}
	}

	for _, v := range two.([]interface{}) {
		if !MemberOfSlice(v, one) {
			new = append(new, v)
		}
	}

	return old, new
}
