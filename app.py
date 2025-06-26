import sqlite3
from flask import Flask, render_template, request, Response, redirect, url_for, jsonify, flash, send_file, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
import pyodbc
import logging
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from dotenv import load_dotenv
from flask import send_from_directory
import base64
from waitress import serve
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
import filetype
import io
from app import Mensaje

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave_secreta_segura")

# ✅ Nueva conexión a PostgreSQL de Render:
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://cinedb_hjod_user:8yEpW4CPOwoEMSXT8og1twzVwaPsM282@dpg-d1eruradbo4c73ess1a0-a/cinedb_hjod'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CACHE_TYPE'] = 'simple'

db = SQLAlchemy(app)
cache = Cache(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Validación de archivos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Código secreto para administradores
ADMIN_SECRET_CODE = "985634"

# Modelo para la tabla usuarios
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Tu clase personalizada, igual que antes
class User(UserMixin):
    def __init__(self, id, email, password, is_admin=False):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

# Login loader que respeta tu lógica
@login_manager.user_loader
def load_user(user_id):
    usuario = Usuario.query.filter_by(id=user_id).first()
    if usuario:
        return User(usuario.id, usuario.email, usuario.password, usuario.is_admin)
    return None



class Pelicula(db.Model):
    __tablename__ = 'peliculas'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100))
    genero = db.Column(db.String(50))
    duracion = db.Column(db.String(20))
    imagen = db.Column(db.LargeBinary)
    trailer = db.Column(db.String(255))

class PeliculaCompleta(db.Model):
    __tablename__ = 'peliculas_completas'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100))
    genero = db.Column(db.String(50))
    duracion = db.Column(db.String(20))
    imagen = db.Column(db.LargeBinary)
    pelicula_completa = db.Column(db.String(255))





@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        is_admin = email.endswith('@admin.com')

        if is_admin and request.form.get('admin_code') != ADMIN_SECRET_CODE:
            flash('Código de administrador incorrecto', 'error')
            return redirect(url_for('register'))

        # Reemplazo de pyodbc: usar SQLAlchemy
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('El correo electrónico ya está registrado', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        nuevo_usuario = Usuario(email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('Registro exitoso. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', logo_url=url_for('obtener_logo'))




@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 🔁 Reemplazamos la consulta con SQLAlchemy
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and check_password_hash(usuario.password, password):
            if usuario.is_admin and request.form.get('admin_code') != ADMIN_SECRET_CODE:
                flash('Código de administrador incorrecto', 'error')
                return redirect(url_for('login'))

            # Creamos objeto User para login_user
            user = User(usuario.id, usuario.email, usuario.password, usuario.is_admin)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Email o contraseña incorrectos', 'error')

    return render_template('login.html', logo_url=url_for('obtener_logo'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def cargar_configuracion():
    try:
        with open('configuracion.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"logo": "logo.png"}



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', logo_url=url_for('obtener_logo'))
    return redirect(url_for('login'))


@app.route('/cartelera', methods=['GET'])
@login_required
@cache.cached(timeout=300)
def cartelera():
    try:
        # Obtener trailers paginados
        page = int(request.args.get('page', 1))
        per_page = 9
        offset = (page - 1) * per_page

        peliculas_query = Pelicula.query.order_by(Pelicula.id.desc()).offset(offset).limit(per_page).all()

        peliculas = [
            {
                "id": peli.id,
                "titulo": peli.titulo,
                "genero": peli.genero,
                "duracion": peli.duracion,
                "imagen": f"data:image/jpeg;base64,{base64.b64encode(peli.imagen).decode('utf-8')}" if peli.imagen else None,
                "trailer": peli.trailer,
            }
            for peli in peliculas_query
        ]

        # Obtener películas completas
        peliculas_completas_query = PeliculaCompleta.query.all()
        peliculas_completas = [
            {
                "id": peli.id,
                "titulo": peli.titulo,
                "genero": peli.genero,
                "duracion": peli.duracion,
                "imagen": url_for('obtener_imagen_pelicula_completa', id=peli.id),
                "pelicula_completa": url_for('obtener_video_pelicula_completa', id=peli.id),
            }
            for peli in peliculas_completas_query
        ]

        return render_template(
            'cartelera.html',
            peliculas=peliculas,
            peliculas_completas=peliculas_completas,
            current_page=page,
            next_page=page + 1,
            prev_page=page - 1 if page > 1 else None,
            logo_url=url_for('obtener_logo')
        )

    except Exception as e:
        return jsonify({'error': str(e)})







@app.route('/buscar')
def buscar():
    query = request.args.get('q', '').strip().lower()
    es_trailer = request.args.get('es_trailer', 'true') == 'true'

    try:
        peliculas = []

        if es_trailer:
            resultados = Pelicula.query.filter(
                (Pelicula.titulo.ilike(f'%{query}%')) | 
                (Pelicula.genero.ilike(f'%{query}%'))
            ).all()

            for fila in resultados:
                imagen = None
                if fila.imagen:
                    imagen_base64 = base64.b64encode(fila.imagen).decode('utf-8')
                    imagen = f"data:image/jpeg;base64,{imagen_base64}"

                peliculas.append({
                    'id': fila.id,
                    'titulo': fila.titulo,
                    'genero': fila.genero,
                    'duracion': fila.duracion,
                    'imagen': imagen,
                    'trailer': fila.trailer
                })

        else:
            resultados = PeliculaCompleta.query.filter(
                (PeliculaCompleta.titulo.ilike(f'%{query}%')) | 
                (PeliculaCompleta.genero.ilike(f'%{query}%'))
            ).all()

            for fila in resultados:
                imagen = None
                if fila.imagen:
                    imagen_base64 = base64.b64encode(fila.imagen).decode('utf-8')
                    imagen = f"data:image/jpeg;base64,{imagen_base64}"

                peliculas.append({
                    'id': fila.id,
                    'titulo': fila.titulo,
                    'genero': fila.genero,
                    'duracion': fila.duracion,
                    'imagen': imagen,
                    'pelicula_completa': url_for('obtener_video_pelicula_completa', id=fila.id)
                })

        return jsonify(peliculas)

    except Exception as e:
        print(f"Error al buscar películas: {e}")
        return jsonify({'error': 'Error en la búsqueda'}), 500





@app.route('/admin')
@login_required
def admin():
    try:
        # Obtener las películas con tráiler
        peliculas_query = Pelicula.query.all()
        peliculas = [
            {
                "id": row.id,
                "titulo": row.titulo,
                "genero": row.genero,
                "duracion": row.duracion,
                "imagen": row.imagen,
                "trailer": row.trailer,
            }
            for row in peliculas_query
        ]

        # Obtener las películas completas
        peliculas_completas_query = PeliculaCompleta.query.all()
        peliculas_completas = [
            {
                "id": row.id,
                "titulo": row.titulo,
                "genero": row.genero,
                "duracion": row.duracion,
                "imagen": row.imagen,
            }
            for row in peliculas_completas_query
        ]

        return render_template(
            'admin.html',
            peliculas=peliculas,
            peliculas_completas=peliculas_completas,
            logo_url=url_for('obtener_logo')
        )

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error en la base de datos'}), 500



@app.route('/agregar_pelicula', methods=['POST'])
@login_required
def agregar_pelicula():
    titulo = request.form['titulo']
    genero = request.form['genero']
    duracion = int(request.form['duracion'])
    trailer = request.form['trailer']
    
    imagen_binaria = None
    if 'imagen' in request.files and allowed_file(request.files['imagen'].filename):
        imagen = request.files['imagen']
        imagen_binaria = imagen.read()  # Leer imagen en binario
    
    try:
        nueva_pelicula = Pelicula(
            titulo=titulo,
            genero=genero,
            duracion=duracion,
            imagen=imagen_binaria,
            trailer=trailer
        )

        db.session.add(nueva_pelicula)
        db.session.commit()

        flash('Película agregada exitosamente.', 'success')
        return redirect(url_for('admin'))

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error al agregar la película'}), 500



@app.route('/imagen_pelicula/<int:id>')
def obtener_imagen_pelicula(id):
    try:
        pelicula = Pelicula.query.get(id)
        if pelicula and pelicula.imagen:
            return send_file(BytesIO(pelicula.imagen), mimetype='image/jpeg')  # Ajusta mimetype si es otro formato
        else:
            return send_file("static/img/default.jpg", mimetype='image/jpeg')  # Imagen por defecto
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error al obtener imagen'}), 500


@app.route('/peliculas_existentes')
def peliculas_existentes():
    try:
        peliculas_query = Pelicula.query.all()
        peliculas = [
            {
                "id": peli.id,
                "titulo": peli.titulo,
                "genero": peli.genero,
                "duracion": peli.duracion,
                "imagen": peli.imagen,
                "trailer": peli.trailer,
            }
            for peli in peliculas_query
        ]
        return render_template('editar_pelicula.html', peliculas=peliculas)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error al obtener películas'}), 500


@app.route('/editar_pelicula/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_pelicula(id):
    pelicula = Pelicula.query.get(id)
    if not pelicula:
        return "Película no encontrada", 404

    if request.method == 'POST':
        # Eliminar película
        if 'eliminar' in request.form:
            try:
                db.session.delete(pelicula)
                db.session.commit()
                flash('Película eliminada exitosamente.', 'success')
                return redirect(url_for('admin'))
            except Exception as e:
                return jsonify({'success': False, 'error': str(e), 'message': 'Error al eliminar la película'}), 500

        # Actualizar película
        titulo = request.form['titulo']
        genero = request.form['genero']
        duracion = int(request.form['duracion'])
        trailer = request.form['trailer']
        imagen_binaria = None

        if 'imagen' in request.files and request.files['imagen'].filename:
            imagen = request.files['imagen']
            imagen_binaria = imagen.read()

        try:
            pelicula.titulo = titulo
            pelicula.genero = genero
            pelicula.duracion = duracion
            pelicula.trailer = trailer

            if imagen_binaria:
                pelicula.imagen = imagen_binaria

            db.session.commit()
            flash('Película editada exitosamente.', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            return jsonify({'success': False, 'error': str(e), 'message': 'Error al editar la película'}), 500

    # Método GET: enviar datos para editar
    pelicula_data = {
        "id": pelicula.id,
        "titulo": pelicula.titulo,
        "genero": pelicula.genero,
        "duracion": pelicula.duracion,
        "trailer": pelicula.trailer
    }

    # Cargar configuración (si la tienes implementada)
    configuracion = cargar_configuracion() if 'cargar_configuracion' in globals() else {}
    logo = configuracion.get('logo', 'logo.png')

    return render_template('editar_pelicula.html', pelicula=pelicula_data, id=id, logo_url=url_for('obtener_logo'))



class Configuracion(db.Model):
    __tablename__ = 'configuracion'
    clave = db.Column(db.String(100), primary_key=True)
    valor = db.Column(db.LargeBinary)



@app.route('/eliminar_pelicula/<int:id>', methods=['POST'])
@login_required
def eliminar_pelicula(id):
    try:
        pelicula = Pelicula.query.get(id)
        if not pelicula:
            flash('Película no encontrada.', 'error')
            return redirect(url_for('admin'))

        db.session.delete(pelicula)
        db.session.commit()
        flash('Película eliminada exitosamente.', 'success')
        return redirect(url_for('admin'))

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error al eliminar película'}), 500


def get_logo_from_db():
    logo = Configuracion.query.filter_by(clave='logo').first()
    return logo.valor if logo and logo.valor else None


def update_logo_in_db(file_data):
    logo = Configuracion.query.filter_by(clave='logo').first()
    if logo:
        logo.valor = file_data
    else:
        logo = Configuracion(clave='logo', valor=file_data)
        db.session.add(logo)
    db.session.commit()


@app.route('/cambiar_logo', methods=['POST'])
@login_required
def cambiar_logo():
    if 'logo' not in request.files:
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('admin'))

    file = request.files['logo']
    if file.filename == '':
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('admin'))

    if file and allowed_file(file.filename):
        file_data = file.read()
        try:
            update_logo_in_db(file_data)
            flash('Logo actualizado correctamente', 'success')
        except Exception as e:
            flash(f'Error al actualizar el logo: {e}', 'error')
    else:
        flash('Tipo de archivo no permitido', 'error')

    return redirect(url_for('admin'))


@app.route('/logo')
def obtener_logo():
    logo_data = get_logo_from_db()
    if logo_data:
        return send_file(BytesIO(logo_data), mimetype='image/png')
    return send_file('static/img/default_logo.png', mimetype='image/png')


@app.context_processor
def inject_logo():
    return {'logo_url': url_for('obtener_logo')}



# Definir la carpeta para almacenar los videos
VIDEO_FOLDER = os.path.join('static', 'videos')
app.config['VIDEO_FOLDER'] = VIDEO_FOLDER


class Pelicula(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100))
    imagen_url = db.Column(db.String(255))
    descripcion = db.Column(db.Text)
    video_url = db.Column(db.String(255))  # si tienes ruta del video


# Crear la carpeta si no existe
if not os.path.exists(VIDEO_FOLDER):
    os.makedirs(VIDEO_FOLDER)

# Ruta del archivo JSON
PELIS_COMPLETAS_JSON = 'peliculas_completas.json'

def cargar_peliculas_completas():
    """Cargar las películas completas desde el archivo JSON."""
    try:
        with open(PELIS_COMPLETAS_JSON, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def guardar_peliculas_completas(peliculas):
    """Guardar las películas completas en el archivo JSON."""
    with open(PELIS_COMPLETAS_JSON, 'w') as f:
        json.dump(peliculas, f, indent=4)

def buscar_peliculas(query, peliculas):
    """Función para buscar películas por título o género."""
    query = query.lower()
    resultados = [pelicula for pelicula in peliculas if query in pelicula['titulo'].lower() or query in pelicula['genero'].lower()]
    return resultados

@app.route('/agregar_pelicula_completa', methods=['POST'])
@login_required
def agregar_pelicula_completa():
    try:
        titulo = request.form['titulo']
        genero = request.form['genero']
        duracion = int(request.form['duracion'])

        imagen_binaria = None
        if 'imagen' in request.files and allowed_file(request.files['imagen'].filename):
            imagen = request.files['imagen']
            imagen_binaria = imagen.read()

        pelicula_binaria = None
        if 'pelicula_completa' in request.files and allowed_file(request.files['pelicula_completa'].filename):
            pelicula = request.files['pelicula_completa']
            pelicula_binaria = pelicula.read()

        if not imagen_binaria or not pelicula_binaria:
            flash("Error: Debes subir una imagen y un video.", "error")
            return redirect(url_for('admin'))

        nueva_pelicula_completa = PeliculaCompleta(
            titulo=titulo,
            genero=genero,
            duracion=duracion,
            imagen=imagen_binaria,
            pelicula_completa=pelicula_binaria
        )

        db.session.add(nueva_pelicula_completa)
        db.session.commit()

        flash('Película completa agregada exitosamente', 'success')
        return redirect(url_for('admin'))

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/imagen_pelicula_completa/<int:id>')
def obtener_imagen_pelicula_completa(id):
    try:
        pelicula = PeliculaCompleta.query.get(id)
        if pelicula and pelicula.imagen:
            image_data = pelicula.imagen
            kind = filetype.guess(image_data)
            mime_type = kind.mime if kind else 'image/jpeg'
            return send_file(BytesIO(image_data), mimetype=mime_type)

        return send_file('static/img/default.jpg', mimetype='image/jpeg')

    except Exception as e:
        print(f"[ERROR] Imagen no cargada: {e}")
        return send_file('static/img/default.jpg', mimetype='image/jpeg')

@app.route('/video_pelicula_completa/<int:id>')
def obtener_video_pelicula_completa(id):
    try:
        pelicula = PeliculaCompleta.query.get(id)
        if not pelicula or not pelicula.pelicula_completa:
            return "Video no encontrado", 404

        video_data = pelicula.pelicula_completa
        video_size = len(video_data)
        video_stream = io.BytesIO(video_data)

        range_header = request.headers.get('Range', None)
        if range_header:
            byte_range = range_header.replace('bytes=', '').split('-')
            start = int(byte_range[0])
            end = int(byte_range[1]) if byte_range[1] else video_size - 1
            length = end - start + 1

            video_stream.seek(start)
            data = video_stream.read(length)

            rv = Response(data, 206, mimetype='video/mp4', direct_passthrough=True)
            rv.headers.add('Content-Range', f'bytes {start}-{end}/{video_size}')
            rv.headers.add('Accept-Ranges', 'bytes')
            rv.headers.add('Content-Length', str(length))
            return rv

        # Si no hay header Range, enviar todo el video
        return Response(video_stream.read(), mimetype='video/mp4')

    except Exception as e:
        print(f"[ERROR] No se pudo reproducir el video: {e}")
        return "Error interno del servidor", 500


@app.route('/peliculas_completas')
@login_required
def peliculas_completas():
    try:
        peliculas_query = PeliculaCompleta.query.all()
        peliculas = [
            {
                "id": peli.id,
                "titulo": peli.titulo,
                "genero": peli.genero,
                "duracion": peli.duracion,
                "imagen": f"data:image/jpeg;base64,{(peli.imagen.encode('base64').decode() if peli.imagen else '')}",
                "pelicula_completa": f"data:video/mp4;base64,{(peli.pelicula_completa.encode('base64').decode() if peli.pelicula_completa else '')}"
            }
            for peli in peliculas_query
        ]
        return render_template('peliculas_completas.html', peliculas=peliculas, logo_url=url_for('obtener_logo'))

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'message': 'Error al cargar películas completas'}), 500


@app.route('/ver_pelicula/<int:pelicula_id>')
def ver_pelicula(pelicula_id):
    try:
        pelicula = PeliculaCompleta.query.get(pelicula_id)
        if not pelicula:
            return "Película no encontrada", 404

        video_data = pelicula.pelicula_completa

        if video_data:
            response = make_response(video_data)
            response.headers.set('Content-Type', 'video/mp4')
            return response
        else:
            return "Archivo de video no encontrado", 404

    except Exception as e:
        print(f"Error al reproducir video: {e}")
        return "Error al reproducir video", 500

@app.route('/editar_pelicula_completa/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_pelicula_completa(id):
    # Verificar si el usuario es admin
    if not current_user.is_admin:
        flash('No tienes permisos para editar películas', 'error')
        return redirect(url_for('index'))

    pelicula = PeliculaCompleta.query.get(id)
    if not pelicula:
        flash('Película no encontrada', 'error')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        if 'eliminar' in request.form:
            try:
                db.session.delete(pelicula)
                db.session.commit()
                flash('Película eliminada con éxito', 'success')
            except Exception as e:
                flash(f'Error al eliminar la película: {e}', 'error')
            return redirect(url_for('admin'))

        # Actualizar datos
        pelicula.titulo = request.form['titulo']
        pelicula.genero = request.form['genero']
        pelicula.duracion = int(request.form['duracion'])

        # Manejo de imagen
        if 'imagen' in request.files:
            file_imagen = request.files['imagen']
            if file_imagen.filename != '':
                pelicula.imagen = file_imagen.read()

        # Manejo de video
        if 'video' in request.files:
            file_video = request.files['video']
            if file_video.filename != '':
                pelicula.pelicula_completa = file_video.read()

        try:
            db.session.commit()
            flash('Película completa editada con éxito', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al editar la película: {e}', 'error')

        return redirect(url_for('admin'))

    # GET: renderizar plantilla con datos
    return render_template(
        'editar_pelicula_completa.html',
        pelicula=pelicula,
        id=id,
        logo_url=url_for('obtener_logo')
    )




@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', email=current_user.email)


@app.route('/api/mensajes', methods=['GET'])
@login_required
def obtener_mensajes():
    receiver = request.args.get('receiver', '')

    if receiver:
        # Filtrar mensajes entre current_user y receiver con condiciones de visibilidad
        mensajes_query = Mensaje.query.filter(
            ((Mensaje.sender_email == current_user.email) & (Mensaje.receiver_email == receiver) & (Mensaje.visible_para_sender == True)) |
            ((Mensaje.sender_email == receiver) & (Mensaje.receiver_email == current_user.email) & (Mensaje.visible_para_receiver == True))
        ).order_by(Mensaje.timestamp.asc()).all()
    else:
        # Todos los mensajes visibles para current_user
        mensajes_query = Mensaje.query.filter(
            ((Mensaje.sender_email == current_user.email) & (Mensaje.visible_para_sender == True)) |
            ((Mensaje.receiver_email == current_user.email) & (Mensaje.visible_para_receiver == True))
        ).order_by(Mensaje.timestamp.asc()).all()

    mensajes = []
    for m in mensajes_query:
        mensajes.append({
            'id': m.id,
            'sender': m.sender_email,
            'receiver': m.receiver_email,
            'contenido': m.contenido,
            'timestamp': m.timestamp.strftime('%H:%M') if m.timestamp else ''
        })

    return jsonify(mensajes)

@app.route('/api/mensajes', methods=['POST'])
@login_required
def enviar_mensaje():
    data = request.json
    contenido = data.get('contenido')
    receiver_email = data.get('receiver')

    if not contenido:
        return jsonify({'error': 'Mensaje vacío'}), 400

    if receiver_email:
        usuario_destino = Usuario.query.filter_by(email=receiver_email).first()
        if not usuario_destino:
            return jsonify({'error': 'Destinatario no encontrado'}), 404

        mensaje = Mensaje(
            sender_email=current_user.email,
            receiver_email=receiver_email,
            contenido=contenido,
            timestamp=datetime.utcnow(),
            visible_para_sender=True,
            visible_para_receiver=True
        )
        db.session.add(mensaje)
        db.session.commit()

        return jsonify({'success': True})

    else:
        # Si no hay destinatario específico, enviar a todos administradores
        if not current_user.is_admin:
            admins = Usuario.query.filter_by(is_admin=True).all()
            for admin in admins:
                mensaje = Mensaje(
                    sender_email=current_user.email,
                    receiver_email=admin.email,
                    contenido=contenido,
                    timestamp=datetime.utcnow(),
                    visible_para_sender=True,
                    visible_para_receiver=True
                )
                db.session.add(mensaje)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Debe especificar un destinatario'}), 400


@app.route('/api/mensajes/<int:id>/eliminar_para_mi', methods=['POST'])
@login_required
def eliminar_para_mi(id):
    mensaje = Mensaje.query.get(id)
    if not mensaje:
        return jsonify({'error': 'Mensaje no encontrado'}), 404

    if mensaje.sender_email == current_user.email:
        mensaje.visible_para_sender = False
    elif mensaje.receiver_email == current_user.email:
        mensaje.visible_para_receiver = False
    else:
        return jsonify({'error': 'No tienes permiso para esta operación'}), 403

    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/mensajes/<int:id>/eliminar_para_todos', methods=['POST'])
@login_required
def eliminar_para_todos(id):
    mensaje = Mensaje.query.get(id)
    if not mensaje:
        return jsonify({'error': 'Mensaje no encontrado'}), 404

    if mensaje.sender_email == current_user.email or current_user.is_admin:
        db.session.delete(mensaje)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'No tienes permiso para esta operación'}), 403



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Render asigna el puerto en PORT
    serve(app, host='0.0.0.0', port=port)
