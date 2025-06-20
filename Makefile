# 컴파일러 및 옵션
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lcrypto



CFLAGS += -DDEBUG -g



# 대상 실행 파일 이름
TARGET = SecureSRA

# 소스 파일 목록
SRCS = api.c secure_test.c
OBJS = $(SRCS:.c=.o)

# 기본 빌드 타겟
all: $(TARGET)

# 링크
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# 컴파일
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리
clean:
	rm -f $(OBJS) $(TARGET)
