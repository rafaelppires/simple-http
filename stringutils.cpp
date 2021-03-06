#include <stringutils.h>
#include <algorithm>
#include <cstring>
//------------------------------------------------------------------------------
std::string StringUtils::MapJoiner::join(const KeyValueMap &map) {
    std::vector<std::string> tojoin;
    for (const auto &kv : map) {
        tojoin.push_back(kv.first + kvSeparator_ + kv.second);
    }
    return joiner_.join(tojoin);
}

//------------------------------------------------------------------------------
std::vector<std::string> StringUtils::split(const std::string &str,
                                            const std::string &sep) {
    char cstr[str.size()+1], *ctx;
    memcpy(cstr, str.c_str(), str.size()+1);
    char *current;
    std::vector<std::string> arr;
    current = strtok_r(cstr, sep.c_str(),&ctx);
    while (current != NULL) {
        arr.push_back(current);
        current = strtok_r(NULL, sep.c_str(),&ctx);
    }
    return arr;
}

//------------------------------------------------------------------------------
std::string StringUtils::replaceAll(std::string str, const std::string &from,
                                    const std::string &to) {
    size_t pos;
    while ((pos = str.find(from)) != std::string::npos) {
        str.replace(pos, from.size(), to);
        pos += to.size();
    }
    return str;
}

//------------------------------------------------------------------------------
std::string StringUtils::tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}
