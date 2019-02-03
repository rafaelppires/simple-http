#include <http1decoder.h>

const std::string eol = "\r\n";
const std::string req =
    "GET /test/bubu HTTP/1.1" + eol + "Host: 127.0.0.1:4445" + eol + eol;

int main() {
    size_t requests_received;
    Http1Decoder decoder;
    for (int i = 0; i < 1e+5; ++i) {
        decoder.addChunk(req + req + req);
        while (decoder.requestReady()) {
            ++requests_received;
            if (requests_received % 5000 == 0)
                printf("%luk Requests\n", requests_received / 1000);
            Request req = decoder.getRequest();
        }
    }
}
