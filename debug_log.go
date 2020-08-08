package main

func debugLog(f string, s ...interface{}) {
	if debugOn {
		logger.Debug(f, s...)
	}
}
