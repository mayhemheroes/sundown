FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
RUN sed -i 's/-Wl//' /repo/Makefile
WORKDIR /repo
RUN make -j8 
RUN clang++ /repo/mayhem/fuzz_sdhtml_is_tag.cpp -fsanitize=fuzzer,address -L /repo -lsundown -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/sundown /
COPY --from=builder /repo /deps
ENV LD_LIBRARY_PATH=/deps
COPY --from=builder /fuzz /fuzz_sdhtml_is_tag
