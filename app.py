import psycopg2
from flask import Flask, render_template, request, Response, redirect, url_for, jsonify, flash, send_file, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
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

app = Flask(__name__)
# Configuración de Flask
app.secret_key = os.environ.get("SECRET_KEY", "e0436a748be72d21e0ddc8cf63fa2d2c17f4c8a72f7ccf0b568e02b6b3db4ed9")

# ✅ Configuración para PostgreSQL con SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://cine_cg13_user:jqX552JwRvrwKzEV2xRmie6X30mrb3Fm@dpg-d3en8rqli9vc739tl64g-a.oregon-postgres.render.com:5432/cine_cg13'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi'}

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Servidor Flask iniciado correctamente.")

# Conexión directa a PostgreSQL (si en algún punto no usas SQLAlchemy)
def get_db_connection():
    try:
        connection = psycopg2.connect(
            host="dpg-d3en8rqli9vc739tl64g-a.oregon-postgres.render.com",
            database="cine_cg13",
            user="cine_cg13_user",
            password="jqX552JwRvrwKzEV2xRmie6X30mrb3Fm",
            port="5432"
        )
        logging.info("Conexión exitosa a PostgreSQL.")
        return connection
    except psycopg2.Error as e:
        logging.error(f"Error en la conexión: {e}")
        raise

def handle_db_error(error):
    return jsonify({'success': False, 'error': str(error), 'message': 'Error en la base de datos'}), 500

def with_db_connection(f):
    def wrapper(*args, **kwargs):
        conn = None
        try:
            conn = get_db_connection()
            return f(conn, *args, **kwargs)
        except psycopg2.Error as e:
            return handle_db_error(e)
        finally:
            if conn:
                conn.close()
    wrapper.__name__ = f.__name__
    return wrapper

# Validación de archivos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# Código secreto para administradores
ADMIN_SECRET_CODE = "985634"


class User(UserMixin):
    def __init__(self, id, email, password, is_admin=False):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password, is_admin FROM Usuarios WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        is_admin = email.endswith('@admin.com')

        if is_admin and request.form.get('admin_code') != ADMIN_SECRET_CODE:
            flash('Código de administrador incorrecto', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM Usuarios WHERE email = %s", (email,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            flash('El correo electrónico ya está registrado', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO Usuarios (email, password, is_admin) VALUES (%s, %s, %s)",
                       (email, hashed_password, is_admin))
        conn.commit()
        conn.close()

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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password, is_admin FROM Usuarios WHERE email = %s", (email,))
        row = cursor.fetchone()
        conn.close()

        if row and check_password_hash(row[2], password):
            if row[3] and request.form.get('admin_code') != ADMIN_SECRET_CODE:
                flash('Código de administrador incorrecto', 'error')
                return redirect(url_for('login'))

            user = User(*row)
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
def cartelera():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Obtener trailers paginados
        page = int(request.args.get('page', 1))
        per_page = 9
        offset = (page - 1) * per_page

        cursor.execute("""
            SELECT id, titulo, genero, duracion, imagen, trailer
            FROM Peliculas
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))

        peliculas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": f"data:image/jpeg;base64,{base64.b64encode(row[4]).decode('utf-8')}" if row[4] else None,
                "trailer": row[5],
            }
            for row in cursor.fetchall()
        ]

        # Películas completas (sin base64, se usa ruta directa a endpoints)
        cursor.execute("SELECT id, titulo, genero, duracion FROM Peliculas_Completas")
        peliculas_completas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": url_for('obtener_imagen_pelicula_completa', id=row[0]),
                "pelicula_completa": url_for('obtener_video_pelicula_completa', id=row[0]),
            }
            for row in cursor.fetchall()
        ]

        conn.close()

        return render_template(
            'cartelera.html',
            peliculas=peliculas,
            peliculas_completas=peliculas_completas,
            current_page=page,
            next_page=page + 1,
            prev_page=page - 1 if page > 1 else None,
            logo_url=url_for('obtener_logo')
        )

    except psycopg2.Error as e:
        return jsonify({'error': str(e)})






@app.route('/buscar')
def buscar():
    query = request.args.get('q', '').strip()
    es_trailer = request.args.get('es_trailer', 'true') == 'true'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if es_trailer:
            sql = """
                SELECT id, titulo, genero, duracion, imagen, trailer 
                FROM Peliculas 
                WHERE LOWER(titulo) LIKE %s OR LOWER(genero) LIKE %s
            """
        else:
            sql = """
                SELECT id, titulo, genero, duracion, imagen 
                FROM Peliculas_Completas 
                WHERE LOWER(titulo) LIKE %s OR LOWER(genero) LIKE %s
            """
        
        like_query = f"%{query.lower()}%"
        cursor.execute(sql, (like_query, like_query))
        filas = cursor.fetchall()
        
        peliculas = []
        for fila in filas:
            id_pelicula = fila[0]
            titulo = fila[1]
            genero = fila[2]
            duracion = fila[3]
            imagen_blob = fila[4]
            
            # Convertir imagen binaria a base64
            imagen = None
            if imagen_blob:
                imagen_base64 = base64.b64encode(imagen_blob).decode('utf-8')
                imagen = f"data:image/jpeg;base64,{imagen_base64}"

            if es_trailer:
                trailer_url = fila[5]
                pelicula = {
                    'id': id_pelicula,
                    'titulo': titulo,
                    'genero': genero,
                    'duracion': duracion,
                    'imagen': imagen,
                    'trailer': trailer_url
                }
            else:
                pelicula_completa_url = url_for('obtener_video_pelicula_completa', id=id_pelicula)
                pelicula = {
                    'id': id_pelicula,
                    'titulo': titulo,
                    'genero': genero,
                    'duracion': duracion,
                    'imagen': imagen,
                    'pelicula_completa': pelicula_completa_url
                }
            
            peliculas.append(pelicula)
        
        return jsonify(peliculas)

    except Exception as e:
        print(f"Error al buscar películas: {e}")
        return jsonify({'error': 'Error en la búsqueda'}), 500
    finally:
        conn.close()




@app.route('/admin')
@login_required
@with_db_connection
def admin(conn):
    try:
        cursor = conn.cursor()

        # Obtener las películas con tráiler
        cursor.execute("SELECT id, titulo, genero, duracion, imagen, trailer FROM Peliculas")
        peliculas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": row[4],
                "trailer": row[5],
            }
            for row in cursor.fetchall()
        ]

        # Obtener las películas completas
        cursor.execute("SELECT id, titulo, genero, duracion, imagen FROM Peliculas_Completas")
        peliculas_completas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": row[4],  # Se mantiene la estructura similar a 'Peliculas'
            }
            for row in cursor.fetchall()
        ]

        return render_template(
            'admin.html',
            peliculas=peliculas,
            peliculas_completas=peliculas_completas,
            logo_url=url_for('obtener_logo')
        )

    except psycopg2.Error as e:
        return jsonify({'error': str(e)})


@app.route('/agregar_pelicula', methods=['POST'])
@with_db_connection
@login_required
def agregar_pelicula(conn):
    titulo = request.form['titulo']
    genero = request.form['genero']
    duracion = int(request.form['duracion'])
    trailer = request.form['trailer']
    
    imagen_binaria = None
    if 'imagen' in request.files and allowed_file(request.files['imagen'].filename):
        imagen = request.files['imagen']
        imagen_binaria = imagen.read()  # Leer el archivo en binario
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Peliculas (titulo, genero, duracion, imagen, trailer)
            VALUES (%s, %s, %s, %s, %s)
        """, (titulo, genero, duracion, imagen_binaria, trailer))
        conn.commit()

        # 🔥 limpiar caché de cartelera para que se actualice al instante
        try:
            cache.delete_memoized(cartelera)
        except Exception:
            pass

        flash('Película agregada exitosamente.', 'success')
        return redirect(url_for('admin'))
    except psycopg2.Error as e:
        return jsonify({'error': str(e)})



@app.route('/imagen_pelicula/<int:id>')
@with_db_connection
def obtener_imagen_pelicula(conn, id):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT imagen FROM Peliculas WHERE id = %s", (id,))
        row = cursor.fetchone()
        if row and row[0]:
            return send_file(BytesIO(row[0]), mimetype='image/jpeg')  # 👈 fijo
        else:
            return send_file(os.path.join("static", "img", "default.jpg"), mimetype='image/jpeg')
    except psycopg2.Error as e:
        return handle_db_error(e)




@app.route('/peliculas_existentes')
@with_db_connection
def peliculas_existentes(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, titulo, genero, duracion, imagen, trailer FROM Peliculas")
        peliculas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": row[4],
                "trailer": row[5],
            }
            for row in cursor.fetchall()
        ]
        return render_template('editar_pelicula.html', peliculas=peliculas)
    except psycopg2.Error as e:
        return jsonify({'error': str(e)})


@app.route('/editar_pelicula/<int:id>', methods=['GET', 'POST'])
@with_db_connection
@login_required
def editar_pelicula(conn, id):
    if request.method == 'POST':
        # Eliminar
        if 'eliminar' in request.form:
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM Peliculas WHERE id = %s", (id,))
                conn.commit()
                flash('Película eliminada exitosamente.', 'success')

                # 🔥 invalidar cache de cartelera para que los cambios se vean
                try:
                    cache.delete_memoized(cartelera)
                except Exception:
                    pass

                return redirect(url_for('admin'))
            except psycopg2.Error as e:
                return handle_db_error(e)

        # Actualizar
        titulo = request.form.get('titulo', '')
        genero = request.form.get('genero', '')
        duracion = int(request.form.get('duracion', 0))
        trailer = request.form.get('trailer', '')
        imagen_binaria = None

        if 'imagen' in request.files and request.files['imagen'].filename:
            imagen_binaria = request.files['imagen'].read()

        try:
            cursor = conn.cursor()
            if imagen_binaria:
                cursor.execute("""
                    UPDATE Peliculas
                    SET titulo = %s, genero = %s, duracion = %s, trailer = %s, imagen = %s
                    WHERE id = %s
                """, (titulo, genero, duracion, trailer, imagen_binaria, id))
            else:
                cursor.execute("""
                    UPDATE Peliculas
                    SET titulo = %s, genero = %s, duracion = %s, trailer = %s
                    WHERE id = %s
                """, (titulo, genero, duracion, trailer, id))

            conn.commit()
            flash('Película editada exitosamente.', 'success')

            # 🔥 invalidar cache de cartelera para que se vea de inmediato
            try:
                cache.delete_memoized(cartelera)
            except Exception:
                pass

            return redirect(url_for('admin'))
        except psycopg2.Error as e:
            return handle_db_error(e)

    # GET: obtener datos para mostrar formulario
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, titulo, genero, duracion, trailer FROM Peliculas WHERE id = %s", (id,))
        pelicula = cursor.fetchone()
        if not pelicula:
            return "Película no encontrada", 404

        pelicula_data = {
            "id": pelicula[0],
            "titulo": pelicula[1],
            "genero": pelicula[2],
            "duracion": pelicula[3],
            "trailer": pelicula[4]
        }
        return render_template('editar_pelicula.html', pelicula=pelicula_data, id=id, logo_url=url_for('obtener_logo'))
    except psycopg2.Error as e:
        return handle_db_error(e)




@app.route('/eliminar_pelicula/<int:id>', methods=['POST'])
@with_db_connection
@login_required
def eliminar_pelicula(conn, id):
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Peliculas WHERE id = %s", (id,))
        conn.commit()
        flash('Película eliminada exitosamente.', 'success')
        return redirect(url_for('admin'))
    except psycopg2.Error as e:
        return jsonify({'error': str(e)})


def get_logo_from_db():
    """Obtiene el logo desde la base de datos."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT valor FROM Configuracion WHERE clave = 'logo'")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[0] else None


def update_logo_in_db(file_data):
    """Actualiza el logo en la base de datos."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE Configuracion SET valor = %s WHERE clave = 'logo'", (file_data,))
    conn.commit()
    conn.close()


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
        update_logo_in_db(file_data)
        flash('Logo actualizado correctamente', 'success')
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

# Guardar película completa en la base de datos
@app.route('/agregar_pelicula_completa', methods=['POST'])
@login_required
def agregar_pelicula_completa():
    try:
        titulo = request.form['titulo']
        genero = request.form['genero']
        duracion = int(request.form['duracion'])

        # Leer imagen como binario
        imagen_binaria = None
        if 'imagen' in request.files and allowed_file(request.files['imagen'].filename):
            imagen = request.files['imagen']
            imagen_binaria = imagen.read()

        # Guardar video en disco y obtener ruta
        video_path = None
        if 'pelicula_completa' in request.files and allowed_file(request.files['pelicula_completa'].filename):
            pelicula = request.files['pelicula_completa']
            if pelicula and allowed_file(pelicula.filename):
                filename = secure_filename(pelicula.filename)
                video_path = os.path.join(app.config['VIDEO_FOLDER'], filename)
                pelicula.save(video_path)  # Guardar en disco

        if not imagen_binaria or not video_path:
            flash("Error: Debes subir una imagen y un video.", "error")
            return redirect(url_for('admin'))

        # Insertar en la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Peliculas_Completas (titulo, genero, duracion, imagen, ruta_video)
            VALUES (%s, %s, %s, %s, %s)
        """, (titulo, genero, duracion, imagen_binaria, video_path))
        conn.commit()
        conn.close()

        # 🔥 limpiar caché de cartelera para que aparezca de inmediato
        try:
            cache.delete_memoized(cartelera)
        except Exception:
            pass

        flash('Película completa agregada exitosamente', 'success')
        return redirect(url_for('admin'))
    except psycopg2.Error as e:
        return jsonify({'error': str(e)})



# 🔹 Ruta para obtener la imagen
@app.route('/imagen_pelicula_completa/<int:id>')
def obtener_imagen_pelicula_completa(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT imagen FROM peliculas_completas WHERE id = %s", (id,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            image_data = row[0]  # BYTEA de la DB
            return send_file(BytesIO(image_data), mimetype='image/jpeg')  # 👈 fijo a jpeg

        # Imagen por defecto si no existe
        return send_file(os.path.join("static", "img", "default.jpg"), mimetype='image/jpeg')

    except Exception as e:
        print(f"[ERROR] Imagen no cargada: {e}")
        return send_file(os.path.join("static", "img", "default.jpg"), mimetype='image/jpeg')


# Obtener video de película completa
@app.route('/video_pelicula_completa/<int:id>')
def obtener_video_pelicula_completa(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Ahora buscamos la ruta del archivo, no el binario
        cursor.execute("SELECT ruta_video FROM Peliculas_Completas WHERE id = %s", (id,))
        row = cursor.fetchone()
        conn.close()

        if not row or not row[0]:
            return "Video no encontrado", 404

        video_path = row[0]

        if not os.path.exists(video_path):
            return "Archivo de video no encontrado en el servidor", 404

        # Soporte para Range (adelantar video)
        range_header = request.headers.get('Range', None)
        if range_header:
            file_size = os.path.getsize(video_path)
            byte_range = range_header.replace('bytes=', '').split('-')
            start = int(byte_range[0]) if byte_range[0] else 0
            end = int(byte_range[1]) if byte_range[1] else file_size - 1
            length = end - start + 1

            with open(video_path, 'rb') as f:
                f.seek(start)
                data = f.read(length)

            rv = Response(data, 206, mimetype='video/mp4', direct_passthrough=True)
            rv.headers.add('Content-Range', f'bytes {start}-{end}/{file_size}')
            rv.headers.add('Accept-Ranges', 'bytes')
            rv.headers.add('Content-Length', str(length))
            return rv

        # Si no se pide rango, devolver el archivo completo
        return send_file(video_path, mimetype='video/mp4')

    except Exception as e:
        print(f"[ERROR] No se pudo reproducir el video: {e}")
        return "Error interno del servidor", 500



@app.route('/peliculas_completas')
@login_required
@with_db_connection
def peliculas_completas(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, titulo, genero, duracion FROM Peliculas_Completas ORDER BY id DESC")
        peliculas = [
            {
                "id": row[0],
                "titulo": row[1],
                "genero": row[2],
                "duracion": row[3],
                "imagen": url_for('obtener_imagen_pelicula_completa', id=row[0]),
                "pelicula_completa": url_for('obtener_video_pelicula_completa', id=row[0])
            }
            for row in cursor.fetchall()
        ]
        return render_template('peliculas_completas.html', peliculas=peliculas, logo_url=url_for('obtener_logo'))
    except psycopg2.Error as e:
        return handle_db_error(e)




@app.route('/ver_pelicula/<int:pelicula_id>')
def ver_pelicula(pelicula_id):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ruta_video FROM Peliculas_Completas WHERE id = %s", (pelicula_id,))
        resultado = cursor.fetchone()

        if not resultado or not resultado[0]:
            return "Película no encontrada", 404

        video_path = resultado[0]

        # Si en algún caso guardaste el binario en DB:
        if isinstance(video_path, (bytes, bytearray)):
            response = make_response(video_path)
            response.headers.set('Content-Type', 'video/mp4')
            return response

        # Si es ruta, servir archivo (obtener_video_pelicula_completa también maneja Range)
        if os.path.isfile(video_path):
            return send_file(video_path, mimetype='video/mp4')
        else:
            return "Archivo de video no encontrado", 404

    except Exception as e:
        logging.exception(f"Error al reproducir video: {e}")
        return "Error al reproducir video", 500
    finally:
        if conn:
            conn.close()


@app.route('/editar_pelicula_completa/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_pelicula_completa(id):
    # Verificar si el usuario es admin
    if not current_user.is_admin:
        flash('No tienes permisos para editar películas', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Buscar la película por su ID
    cursor.execute("SELECT id, titulo, genero, duracion, imagen, ruta_video FROM peliculas_completas WHERE id = %s", (id,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        flash('Película no encontrada', 'error')
        return redirect(url_for('admin'))

    # Convertir la fila a diccionario para usar en la plantilla
    pelicula = {
        "id": row[0],
        "titulo": row[1],
        "genero": row[2],
        "duracion": row[3],
        "imagen": row[4],
        "ruta_video": row[5]
    }

    if request.method == 'POST':
        # Si se presiona el botón "Eliminar"
        if 'eliminar' in request.form:
            cursor.execute("DELETE FROM peliculas_completas WHERE id = %s", (id,))
            conn.commit()
            conn.close()
            
            # Limpiar caché de cartelera
            try:
                cache.clear()
            except Exception:
                pass
            
            flash('Película eliminada con éxito', 'success')
            return redirect(url_for('admin'))

        # Datos del formulario
        titulo = request.form['titulo']
        genero = request.form['genero']
        duracion = int(request.form['duracion'])

        # Manejo de imagen
        imagen = None
        if 'imagen' in request.files:
            file_imagen = request.files['imagen']
            if file_imagen.filename != '':
                imagen = file_imagen.read()

        # Manejo de video (se guarda en disco, no en la base de datos)
        ruta_video = None
        if 'video' in request.files:
            file_video = request.files['video']
            if file_video.filename != '':
                filename = secure_filename(file_video.filename)
                video_path = os.path.join(app.config['VIDEO_FOLDER'], filename)
                file_video.save(video_path)
                ruta_video = video_path

        # Preparar la consulta de actualización dinámicamente
        if imagen and ruta_video:
            cursor.execute("""
                UPDATE peliculas_completas
                SET titulo = %s, genero = %s, duracion = %s, imagen = %s, ruta_video = %s
                WHERE id = %s
            """, (titulo, genero, duracion, imagen, ruta_video, id))
        elif imagen:
            cursor.execute("""
                UPDATE peliculas_completas
                SET titulo = %s, genero = %s, duracion = %s, imagen = %s
                WHERE id = %s
            """, (titulo, genero, duracion, imagen, id))
        elif ruta_video:
            cursor.execute("""
                UPDATE peliculas_completas
                SET titulo = %s, genero = %s, duracion = %s, ruta_video = %s
                WHERE id = %s
            """, (titulo, genero, duracion, ruta_video, id))
        else:
            cursor.execute("""
                UPDATE peliculas_completas
                SET titulo = %s, genero = %s, duracion = %s
                WHERE id = %s
            """, (titulo, genero, duracion, id))

        # Confirmar cambios
        conn.commit()
        conn.close()

        # Limpiar caché de cartelera para que se vea de inmediato
        try:
            cache.clear()
        except Exception:
            pass

        flash('Película completa editada con éxito', 'success')
        return redirect(url_for('admin'))

    conn.close()
    return render_template(
        'editar_pelicula_completa.html',
        pelicula=pelicula,
        id=id,
        logo_url=url_for('obtener_logo')
    )




# Ruta de chat
@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', email=current_user.email)

# Obtener administradores
@app.route('/api/administradores', methods=['GET'])
@login_required
def obtener_administradores():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT email FROM Usuarios
        WHERE is_admin = 1
    """)
    rows = cursor.fetchall()
    conn.close()
    
    admins = [{'email': row[0]} for row in rows]
    return jsonify(admins)

# Obtener chats (contactos)
@app.route('/api/chats', methods=['GET'])
@login_required
def obtener_chats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if current_user.is_admin:
        # Si es admin, obtener todos los usuarios que han enviado mensajes
        cursor.execute("""
            SELECT DISTINCT
                CASE
                    WHEN sender_email = ? THEN receiver_email
                    ELSE sender_email
                END as contact_email,
                (SELECT is_admin FROM Usuarios WHERE email = contact_email) as is_admin,
                (SELECT MAX(timestamp) FROM Mensajes 
                 WHERE (sender_email = ? AND receiver_email = contact_email) 
                    OR (sender_email = contact_email AND receiver_email = ?)) as last_time,
                (SELECT contenido FROM Mensajes 
                WHERE ((sender_email = ? AND receiver_email = contact_email) 
                    OR (sender_email = contact_email AND receiver_email = ?))
                ORDER BY timestamp DESC LIMIT 1) as last_message

            FROM Mensajes
            WHERE sender_email = ? OR receiver_email = ?
            GROUP BY contact_email
            ORDER BY last_time DESC 
        """, (current_user.email, current_user.email, current_user.email, current_user.email, current_user.email, current_user.email, current_user.email))
    else:
        # Si es usuario normal, obtener solo los administradores que le han enviado mensajes
        cursor.execute("""
            SELECT DISTINCT
                CASE
                    WHEN sender_email = ? THEN receiver_email
                    ELSE sender_email
                END as contact_email,
                (SELECT is_admin FROM Usuarios WHERE email = contact_email) as is_admin,
                (SELECT MAX(timestamp) FROM Mensajes 
                 WHERE (sender_email = ? AND receiver_email = contact_email) 
                    OR (sender_email = contact_email AND receiver_email = ?)) as last_time,
                (SELECT contenido FROM Mensajes 
                WHERE ((sender_email = ? AND receiver_email = contact_email) 
                    OR (sender_email = contact_email AND receiver_email = ?))
                ORDER BY timestamp DESC LIMIT 1)

            FROM Mensajes
            WHERE (sender_email = ? OR receiver_email = ?)
            AND ((SELECT is_admin FROM Usuarios WHERE email = contact_email) = 1 OR sender_email = ?)
            GROUP BY contact_email
            ORDER BY last_time DESC
        """, (current_user.email, current_user.email, current_user.email, current_user.email, current_user.email, current_user.email, current_user.email, current_user.email))
    
    rows = cursor.fetchall()
    conn.close()
    
    chats = []
    for row in rows:
        if row[0] != current_user.email:  # Evitar mostrar chats con uno mismo
            formatted_time = ""
            if row[2]:
                timestamp = datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S')
                today = datetime.now()
                if timestamp.date() == today.date():
                    formatted_time = timestamp.strftime('%H:%M')
                elif (today.date() - timestamp.date()).days == 1:
                    formatted_time = "Ayer"
                else:
                    formatted_time = timestamp.strftime('%d/%m/%Y')
            
            chats.append({
                'email': row[0],
                'isAdmin': bool(row[1]),
                'time': formatted_time,
                'lastMessage': row[3] if row[3] else ''
            })
    
    return jsonify(chats)

# Obtener mensajes
@app.route('/api/mensajes', methods=['GET'])
@login_required
def obtener_mensajes():
    receiver = request.args.get('receiver', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if receiver:
        # Si hay un destinatario específico, mostrar solo esa conversación
        cursor.execute("""
            SELECT id, sender_email, receiver_email, contenido, timestamp
            FROM Mensajes
            WHERE
                ((sender_email = ? AND receiver_email = ? AND visible_para_sender = 1)
                OR (sender_email = ? AND receiver_email = ? AND visible_para_receiver = 1))
            ORDER BY timestamp ASC
        """, (current_user.email, receiver, receiver, current_user.email))
    else:
        # Si no hay destinatario, mostrar todos los mensajes del usuario
        cursor.execute("""
            SELECT id, sender_email, receiver_email, contenido, timestamp
            FROM Mensajes
            WHERE
                (sender_email = ? AND visible_para_sender = 1)
                OR (receiver_email = ? AND visible_para_receiver = 1)
            ORDER BY timestamp ASC
        """, (current_user.email, current_user.email))
    
    rows = cursor.fetchall()
    conn.close()
    
    mensajes = []
    for row in rows:
        # row[4] ya es datetime
        formatted_time = row[4].strftime('%H:%M')
        
        mensajes.append({
            'id': row[0],
            'sender': row[1],
            'receiver': row[2],
            'contenido': row[3],
            'timestamp': formatted_time
        })
    
    return jsonify(mensajes)


# Enviar mensaje
@app.route('/api/mensajes', methods=['POST'])
@login_required
def enviar_mensaje():
    data = request.json
    contenido = data.get('contenido')
    receiver = data.get('receiver')
    
    if not contenido:
        return jsonify({'error': 'Mensaje vacío'}), 400
    
    # Verificar si el destinatario existe
    if receiver:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM Usuarios WHERE email = ?", (receiver,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Destinatario no encontrado'}), 404
        
        # Insertar el mensaje
        cursor.execute("""
            INSERT INTO Mensajes (sender_email, receiver_email, contenido, timestamp, visible_para_sender, visible_para_receiver)
            VALUES (%s, %s, %s, NOW(), 1, 1)
        """, (current_user.email, receiver, contenido))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    else:
        # Si no hay destinatario específico, enviar mensaje a todos los administradores
        if not current_user.is_admin:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Obtener todos los administradores
            cursor.execute("SELECT email FROM Usuarios WHERE is_admin = 1")
            admins = cursor.fetchall()
            
            for admin in admins:
                cursor.execute("""
                    INSERT INTO Mensajes (sender_email, receiver_email, contenido, timestamp, visible_para_sender, visible_para_receiver)
                    VALUES (%s, %s, %s, NOW(), 1, 1)
                """, (current_user.email, admin[0], contenido))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Debe especificar un destinatario'}), 400

# Eliminar solo para mi
@app.route('/api/mensajes/<int:id>/eliminar_para_mi', methods=['POST'])
@login_required
def eliminar_para_mi(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar primero si el mensaje existe y pertenece al usuario
    cursor.execute("""
        SELECT sender_email, receiver_email FROM Mensajes WHERE id = ?
    """, (id,))
    
    mensaje = cursor.fetchone()
    if not mensaje:
        conn.close()
        return jsonify({'error': 'Mensaje no encontrado'}), 404
    
    # Actualizar la visibilidad según si es remitente o destinatario
    if mensaje[0] == current_user.email:  # Es el remitente
        cursor.execute("""
            UPDATE Mensajes SET visible_para_sender = 0 WHERE id = ?
        """, (id,))
    elif mensaje[1] == current_user.email:  # Es el destinatario
        cursor.execute("""
            UPDATE Mensajes SET visible_para_receiver = 0 WHERE id = ?
        """, (id,))
    else:
        conn.close()
        return jsonify({'error': 'No tienes permiso para esta operación'}), 403
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Eliminar para todos (solo si es el remitente o admin)
@app.route('/api/mensajes/<int:id>/eliminar_para_todos', methods=['POST'])
@login_required
def eliminar_para_todos(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar primero si el mensaje existe
    cursor.execute("""
        SELECT sender_email FROM Mensajes WHERE id = ?
    """, (id,))
    
    mensaje = cursor.fetchone()
    if not mensaje:
        conn.close()
        return jsonify({'error': 'Mensaje no encontrado'}), 404
    
    # Solo el remitente o un administrador puede eliminar para todos
    if mensaje[0] == current_user.email or current_user.is_admin:
        cursor.execute("DELETE FROM Mensajes WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    else:
        conn.close()
        return jsonify({'error': 'No tienes permiso para esta operación'}), 403



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Render asigna el puerto en PORT
    serve(app, host='0.0.0.0', port=port)
