#ifndef _HTTP1_DECODER_H_
#define _HTTP1_DECODER_H_

#include <httpresponse.h>
#include <httprequest.h>
#include <tcpconnection.h>
#include <queue>
#include <mutex>
#include <string>

//------------------------------------------------------------------------------
class Http1Decoder {
   public:
    Http1Decoder();
    Http1Decoder(Http1Decoder &&);
    Http1Decoder &operator=(Http1Decoder &&);
    void addChunk(const std::string &input);
    Response requestReply(EndpointConnection &, const Request &r);
    bool getResponse(Response &);
    bool getRequest(Request &);
    void setHead();

   private:
    enum State { START, HEADER, BODY, CHUNKED };

    bool start_state();
    bool header_state();
    bool body_state();
    bool chunked_state();
    void reset();
    std::string stateString();

    State s_;
    std::string buffer_;
    RequestBuilder  request_;
    ResponseBuilder response_;
    std::recursive_mutex buffer_mutex_;  // crit. section is object state 

    std::queue<ResponseBuilder> responsequeue_;
    std::queue<RequestBuilder> requestqueue_;
    std::mutex request_mutex_, response_mutex_;  // one per queue

    int content_len_;
    bool body_mustnot_, head_, is_request_;
    size_t decoded_messages_;
};

//------------------------------------------------------------------------------
class StatusLine {
   public:
    StatusLine() : code_(-1) {}
    static StatusLine parse(const std::string &, size_t *pos = nullptr);

   private:
    std::string protocol_, message_, uri_;
    bool request_;
    int code_;
    friend class Http1Decoder;
};

//------------------------------------------------------------------------------
#endif
