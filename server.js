const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'cbtis009secret';
const usuarios = {};

app.post('/registro', async (req, res) => {
  const { control, nombre, especialidad, semestre, grupo, password } = req.body;
  if (!control || control.length !== 14 || !control.includes('009')) {
    return res.status(400).json({ error: 'Número de control inválido' });
  }
  if (usuarios[control]) {
    return res.status(400).json({ error: 'Este número de control ya está registrado' });
  }
  const hash = await bcrypt.hash(password, 10);
  usuarios[control] = { control, nombre, especialidad, semestre, grupo, password: hash };
  res.json({ mensaje: 'Registro exitoso' });
});

app.post('/login', async (req, res) => {
  const { control, especialidad, password } = req.body;
  const user = usuarios[control];
  if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Contraseña incorrecta' });
  if (user.especialidad !== especialidad) return res.status(400).json({ error: 'Especialidad incorrecta' });
  const token = jwt.sign({ control, nombre: user.nombre }, SECRET, { expiresIn: '8h' });
  res.json({ token, usuario: { control, nombre: user.nombre, especialidad: user.especialidad, semestre: user.semestre, grupo: user.grupo } });
});

const posts = [];
app.get('/posts', (req, res) => res.json(posts));
app.post('/posts', (req, res) => {
  const { token, texto } = req.body;
  try {
    const user = jwt.verify(token, SECRET);
    posts.unshift({ id: Date.now(), nombre: user.nombre, control: user.control, texto, tiempo: new Date().toLocaleString() });
    res.json({ mensaje: 'Post publicado' });
  } catch { res.status(401).json({ error: 'No autorizado' }); }
});

app.listen(3000, () => console.log('Servidor CBTIS009 corriendo en http://localhost:3000'));