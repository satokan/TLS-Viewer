FROM public.ecr.aws/lambda/python:3.11 as builder

# Install build dependencies
RUN yum update -y && \
    yum install -y git cmake3 ninja-build openssl11-devel gcc gcc-c++ make pkgconfig && \
    ln -sf /usr/bin/cmake3 /usr/bin/cmake

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build liboqs
WORKDIR /build
RUN git clone --branch main --single-branch https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs/build
RUN cmake3 -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja-build && \
    ninja-build install

# Build pqcscan
WORKDIR /build
RUN git clone https://github.com/anvilsecure/pqcscan.git
WORKDIR /build/pqcscan
# Ensure it finds liboqs
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_LDFLAGS="-L/usr/local/lib -loqs"
# Note: pqcscan is Rust, so CGO env vars might not apply directly unless it uses cgo (it's Rust).
# Rust `oqs-sys` or similar crate usually looks for pkg-config or specific env vars.
# Let's set PKG_CONFIG_PATH just in case, and LIBRARY_PATH.
ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"
ENV LIBRARY_PATH="/usr/local/lib"
ENV LD_LIBRARY_PATH="/usr/local/lib"

RUN cargo build --release

# --- Runtime Stage ---
FROM public.ecr.aws/lambda/python:3.11

# Copy liboqs shared libraries
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
# Update ldconfig (or just set env var)
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

# Copy pqcscan binary
COPY --from=builder /build/pqcscan/target/release/pqcscan /usr/local/bin/pqcscan

# Install Python dependencies
COPY requirements.txt .
# Remove psycopg2-binary and use psycopg2-binary (Lambda usually needs binary or compile)
# psycopg2-binary works on Linux usually.
RUN pip install --default-timeout=100 -r requirements.txt

# Copy application code
COPY scanner/ scanner/
COPY run_scan.py .
COPY majestic_million.csv .

# Set the CMD to your handler (to be created)
CMD [ "scanner.lambda_handler.handler" ]
