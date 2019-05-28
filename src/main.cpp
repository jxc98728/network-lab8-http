#include "httpserver.h"

using namespace HttpServer;

int main(void)
{
    Server server;

    server.Get("/dir/test.html", [](const Request &req, Response &res) {
        std::vector<char> buf;
        if (Utils::loadFile("res/html/test.html", buf))
        {
            res.status = 200;
            res.setContent(&buf[0], buf.size(), "text/html");
        }
    });

    server.Get("/dir/noimg.html", [](const Request &req, Response &res) {
        std::vector<char> buf;
        if (Utils::loadFile("res/html/noimg.html", buf))
        {
            res.status = 200;
            res.setContent(&buf[0], buf.size(), "text/html");
        }
    });

    server.Get("/dir/test.jpg|/img/lena.jpg", [](const Request &req, Response &res) {
        std::vector<char> buf;
        if (Utils::loadFile("res/img/lena.jpg", buf))
        {
            res.status = 200;
            res.setContent(&buf[0], buf.size(), "image/jpeg");
        }
    });

    server.Get("/dir/test.txt", [](const Request &req, Response &res) {
        std::vector<char> buf;
        if (Utils::loadFile("res/txt/test.txt", buf))
        {
            res.status = 200;
            res.setContent(&buf[0], buf.size(), "text/plain");
        }
    });

    server.Post("/dir/dopost", [](const Request &req, Response &res) {
        std::regex r("login=([a-zA-Z0-9]*)&pass=([a-zA-Z0-9]*)");
        std::smatch m;
        if (std::regex_match(req.body, m, r))
        {
            auto login = std::string(m[1]);
            auto pass = std::string(m[2]);
            res.status = 200;
            if (login == "3160101309" && pass == "1309")
            {
                res.setContent("<html><body>Login success!</body></html>", "text/html");
            }
            else
            {
                res.setContent("<html><body>Login failure!</body></html>", "text/html");
            }
        }
    });

    server.start("localhost", 1309);
}