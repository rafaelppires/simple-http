#include <errno.h>
#include <http1decoder.h>
#ifdef ENCLAVED
#include <my_wrappers.h>
#endif

using HttpStrings::crlf;
//------------------------------------------------------------------------------
// HTTP1 DECODER
//------------------------------------------------------------------------------
Http1Decoder::Http1Decoder()
    : s_(START), head_(false), body_mustnot_(false), decoded_messages_(0) {}

//------------------------------------------------------------------------------
std::string Http1Decoder::stateString() {
    switch (s_) {
        case START:
            return "START";
        case HEADER:
            return "HEADER";
        case BODY:
            return "BODY";
        case CHUNKED:
            return "CHUNKED";
        default:
            return "UNK";
    }
}

//------------------------------------------------------------------------------
void Http1Decoder::setHead() { head_ = true; }

//------------------------------------------------------------------------------
size_t coun = 0;
void Http1Decoder::addChunk(const std::string& input) {
    buffer_ += input;
    if (buffer_.empty()) {
        printf("Shouldn`t be processing an empty buffer\n");
        return;
    }
#if 0
    printf(">%lu [%lx] (%s) --->%s<--\n", ++coun, this, stateString().c_str(),
           buffer_.c_str());
#endif
    do {
        switch (s_) {
            case START:
                if (start_state()) break;
            case HEADER:
                if (header_state()) break;
            case BODY:
                if (body_state()) break;
            case CHUNKED:
                if (chunked_state()) break;
            default:
                throw std::runtime_error("HTTP Decoder unknown state: " +
                                            std::to_string(s_));
        };
    } while (!buffer_.empty() &&
             buffer_.find(crlf + crlf) != std::string::npos);
}

//------------------------------------------------------------------------------
bool Http1Decoder::start_state() {
    // printf("[%lx] start_state\n", this);
    s_ = HEADER;  // potentially avoid concurrency issues with req/rep Ready()

    size_t headerstart;
    StatusLine sl = StatusLine::parse(buffer_, &headerstart);
    request_ = sl.request_;

    if (request_) {
        requestqueue_.emplace(requestqueue_.end());
        RequestBuilder& request = requestqueue_.back();
        request.protocol(sl.protocol_)
            .method(sl.message_)
            .url(UrlBuilder::parse("http://0:0" + sl.uri_));
    } else {
        responsequeue_.emplace(responsequeue_.end());
        ResponseBuilder& response = responsequeue_.back();
        response.protocol(sl.protocol_).code(sl.code_).message(sl.message_);
        body_mustnot_ = head_ || (sl.code_ >= 100 && sl.code_ < 199) ||
                        sl.code_ == 204 || sl.code_ == 304;
    }
    content_len_ = -1;  // < 0 Makes it read Content-Lenght later

    buffer_.erase(0, headerstart);
    return buffer_.empty();
}

//------------------------------------------------------------------------------
bool Http1Decoder::header_state() {
    // printf("[%lx] header_state", this);
    size_t headerend = buffer_.find(crlf + crlf);
    if (headerend == std::string::npos) {
        return true;  // incomplete, wait more data
    }

    ReqRepBuilder& reqrep =
        request_ ? reinterpret_cast<ReqRepBuilder&>(requestqueue_.back())
                 : reinterpret_cast<ReqRepBuilder&>(responsequeue_.back());

    reqrep.headers(HeadersBuilder::parse(buffer_.substr(0, headerend)));
    buffer_.erase(0, headerend + 4);

    if (body_mustnot_) {
        printf("It's a body must not\n");
        reset();
        return true;  // finished
    }

    /*if (tolower(reqrep.getHeaderValue("Connection")) == "close") {
printf("It's a connection close Header: <%s>\n",
reqrep.getHeaderValue(HttpStrings::transfer_enc).c_str());
        content_len_ = 0;
        s_ = BODY;
        return false;  // keep reading the body
    }//*/

    if (tolower(reqrep.getHeaderValue(HttpStrings::transfer_enc)) ==
        "chunked") {
        s_ = CHUNKED;
        content_len_ = 0;
        addChunk("");
        return true;  // it's a chunked message, skip BODY case
    } else {
        s_ = BODY;
        return false;  // Content-Length may be 0 (in case buffer_ may be
                       // empty)
    }
}
//------------------------------------------------------------------------------
bool Http1Decoder::body_state() {
    // printf("[%lx] body_state", this);
    ReqRepBuilder& reqrep =
        request_ ? reinterpret_cast<ReqRepBuilder&>(requestqueue_.back())
                 : reinterpret_cast<ReqRepBuilder&>(responsequeue_.back());

    if (content_len_ < 0) {
        std::string lenstr;
        lenstr = reqrep.getHeaderValue(HttpStrings::content_len);
        if (lenstr.empty() && reqrep.getHeaderValue("Connection") == "close") {
            if (!buffer_.empty()) reqrep.appendBody(buffer_);
            buffer_.clear();
            reset();
            return true;
        }

        content_len_ = lenstr.empty() ? 0 : std::stoi(lenstr);
    }

    if (content_len_ > 0 && buffer_.size() > 0) {
        size_t consume = std::min(buffer_.size(), (size_t)content_len_);
        reqrep.appendBody(buffer_.substr(0, consume));
        buffer_.erase(0, consume);
        content_len_ -= consume;
    }

    if (content_len_ == 0) {
        reset();
        return true;
    }

    return true;
}

//------------------------------------------------------------------------------
bool Http1Decoder::chunked_state() {
    size_t pos = buffer_.find(crlf);
    if (pos == std::string::npos) return true;

    unsigned size = std::stoi(buffer_.substr(0, pos), nullptr, 16);

    if (buffer_.size() < pos + crlf.size() + size)
        return true;  // Chunk not  yet complete

    buffer_.erase(0, pos + crlf.size());
    if (size == 0) {
        reset();
        return true;
    }

    content_len_ += size;
    pos = buffer_.find(crlf);
    if (pos == std::string::npos) return true;

    std::string chunk = buffer_.substr(0, pos);
    if (content_len_ >= chunk.size()) {
        ResponseBuilder& response = responsequeue_.back();
        response.appendBody(chunk);
        buffer_.erase(0, pos + crlf.size());
        content_len_ -= chunk.size();
        if (!buffer_.empty()) addChunk("");
    }
    return true;
}

//------------------------------------------------------------------------------
void Http1Decoder::reset() {
    // printf("---------\n");
    ++decoded_messages_;
    head_ = false;
    body_mustnot_ = false;
    s_ = START;
}

//------------------------------------------------------------------------------
bool Http1Decoder::responseReady() const {
    if (responsequeue_.size() > 1)
        return true;
    else if (!responsequeue_.empty())
        return s_ == START;
    return false;
}

//------------------------------------------------------------------------------
bool Http1Decoder::requestReady() const {
    if (requestqueue_.size() > 1)
        return true;
    else if (!requestqueue_.empty())
        return s_ == START;
    return false;
}

//------------------------------------------------------------------------------
Response Http1Decoder::getResponse() {
    if (!responseReady()) return Response();
    ResponseBuilder ret;
    std::swap(ret, responsequeue_.front());
    responsequeue_.pop_front();
    return ret.build();
}

//------------------------------------------------------------------------------
Request Http1Decoder::getRequest() {
    if (!requestReady()) return Request();
    RequestBuilder ret;
    std::swap(ret, requestqueue_.front());
    requestqueue_.pop_front();
    return ret.build();
}

//------------------------------------------------------------------------------
// STATUS LINE
//------------------------------------------------------------------------------
StatusLine StatusLine::parse(const std::string& input, size_t* lastpos) {
    StatusLine ret;
    std::string in = ltrim_copy(input);
    size_t diff = in.size() - input.size();
    size_t pos = in.find('\n');

    if (pos != std::string::npos) {
        std::string statusline(trim_copy(in.substr(0, pos)));
        auto pieces = StringUtils::split(statusline, " ");
        if (pieces.size() < 3) {
            for (auto& p : pieces) printf("piece: %s\n", p.c_str());
            throw std::runtime_error(
                "Invalid status line with " + std::to_string(pieces.size()) +
                " pieces: '" + statusline + "' in:[" + in + "]");
        }
        std::string first = trim_copy(pieces.front()),
                    last = trim_copy(pieces.back());
        if (first.find("HTTP") == 0)
            ret.request_ = false;
        else if (last.find("HTTP") == 0)
            ret.request_ = true;
        else
            throw std::runtime_error("StatusLine: only HTTP is supported");

        if (ret.request_) {
            ret.protocol_ = last;
            ret.message_ = first;
            ret.uri_ = pieces[1];
        } else {
            ret.protocol_ = first;
            ret.code_ = std::stoi(pieces[1]);
            ret.message_ = Joiner::on(" ").join(
                std::vector<std::string>(pieces.begin() + 2, pieces.end()));
        }
    } else {
        throw std::runtime_error("StatusLine: illegal input");
    }

    if (lastpos != nullptr) *lastpos = pos + diff;
    return ret;
}

//------------------------------------------------------------------------------