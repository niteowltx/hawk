
TARGET=hawk
INS_DIR=/usr/local/bin

all:	$(TARGET)

clean:
	rm -f $(TARGET)

install:
	install -D $(TARGET) ${INS_DIR}/$(TARGET)

check:
	cppcheck -q *.[ch]
