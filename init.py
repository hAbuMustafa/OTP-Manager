from livereload import Server
from app import app

server = Server(app.wsgi_app)
server.watch("templates/*.html")
server.watch("static/*")
server.serve(port=5000)
