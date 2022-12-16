
TARGET=hawk

all:	$(TARGET)

clean:
	rm -f $(TARGET)

install:
	install -D $(TARGET) /usr/local/bin/$(TARGET)
