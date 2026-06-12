const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Mercado Pago (NOVA API)
const client = new MercadoPagoConfig({ 
    accessToken: process.env.MERCADO_PAGO_ACCESS_TOKEN,
    options: {
        timeout: 5000,
        idempotencyKey: 'abc',
        headers: {
            'X-Platform-Id': 'backend'
        }
    }
});

// Configuração do Supabase (para upload de imagens)
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Configuração do banco de dados
const pool = new Pool({
    connectionString: process.env.SUPABASE_DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Configuração do Multer (upload em memória)
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB max
});

// Middlewares
app.use(cors({
    origin: ['https://dropsetnutri.netlify.app', 'http://localhost:3000', 'http://localhost:5500'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Teste de conexão
app.get('/api/test', async (req, res) => {
    try {
        const client = await pool.connect();
        await client.query('SELECT NOW()');
        client.release();
        res.json({ status: 'OK', message: 'Servidor e banco conectados!' });
    } catch (error) {
        res.status(500).json({ status: 'ERROR', message: error.message });
    }
});

// ==================== AUTENTICAÇÃO ====================

function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Token não fornecido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'dropset2025seguro!', (err, usuario) => {
        if (err) {
            return res.status(403).json({ erro: 'Token inválido ou expirado' });
        }
        req.usuario = usuario;
        next();
    });
}

// Middleware para verificar se é ADMIN
function verificarAdmin(req, res, next) {
    autenticarToken(req, res, () => {
        // ✅ EMAIL DO ADMINISTRADOR CONFIGURADO
        if (req.usuario.email === 'lucasteste@gmail.com') {
            next();
        } else {
            res.status(403).json({ erro: 'Acesso negado: Apenas administradores.' });
        }
    });
}

// Registro
app.post('/api/registro', async (req, res) => {
    try {
        const { nome, email, telefone, senha } = req.body;
        
        if (!nome || !email || !senha) {
            return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios' });
        }

        const hashedSenha = await bcrypt.hash(senha, 10);
        
        const result = await pool.query(
            'INSERT INTO usuarios (nome, email, telefone, senha_hash) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, telefone, created_at',
            [nome, email, telefone || null, hashedSenha]
        );

        const usuario = result.rows[0];
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'dropset2025seguro!',
            { expiresIn: '7d' }
        );

        console.log('✅ Registro realizado:', email);
        res.status(201).json({ 
            mensagem: 'Usuário criado com sucesso',
            usuario,
            token
        });
    } catch (error) {
        console.error('❌ ERRO NO REGISTRO:', error.message);
        if (error.code === '23505') {
            res.status(409).json({ erro: 'Email já cadastrado' });
        } else {
            res.status(500).json({ erro: 'Erro interno ao registrar' });
        }
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
        }

        const result = await pool.query(
            'SELECT id, nome, email, telefone, senha_hash, created_at FROM usuarios WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha inválidos' });
        }

        const usuario = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'Email ou senha inválidos' });
        }

        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'dropset2025seguro!',
            { expiresIn: '7d' }
        );

        delete usuario.senha_hash;

        console.log('✅ Login realizado:', email);
        res.json({ 
            mensagem: 'Login realizado com sucesso',
            usuario,
            token
        });
    } catch (error) {
        console.error('❌ ERRO NO LOGIN:', error.message);
        res.status(500).json({ erro: 'Erro interno ao fazer login' });
    }
});

// ==================== PRODUTOS (PÚBLICO) ====================

// Listar produtos para o cliente (só estoque > 0)
app.get('/api/produtos', async (req, res) => {
    try {
        const { q, categoria, id } = req.query;
        
        let query = 'SELECT * FROM produtos WHERE estoque > 0';
        const values = [];
        let paramIndex = 1;

        if (id) {
            query += ` AND id = $${paramIndex}`;
            values.push(id);
            paramIndex++;
        }

        if (categoria) {
            query += ` AND categoria = $${paramIndex}`;
            values.push(categoria);
            paramIndex++;
        }

        if (q) {
            query += ` AND (LOWER(nome) LIKE $${paramIndex} OR LOWER(descricao) LIKE $${paramIndex})`;
            values.push(`%${q.toLowerCase()}%`);
            paramIndex++;
        }

        query += ' ORDER BY nome ASC';
        
        const result = await pool.query(query, values);
        res.json(result.rows);
    } catch (error) {
        console.error('❌ ERRO AO BUSCAR PRODUTOS:', error.message);
        res.status(500).json({ erro: 'Erro ao buscar produtos' });
    }
});

// ==================== ADMIN (COM UPLOAD) ====================

// 1. Listar TODOS os produtos (inclusive esgotados)
app.get('/api/admin/produtos', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM produtos ORDER BY id DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('❌ ERRO ADMIN LISTAR:', error.message);
        res.status(500).json({ erro: 'Erro ao listar produtos' });
    }
});

// 2. ROTA DE UPLOAD DE IMAGEM
app.post('/api/admin/upload-imagem', verificarAdmin, upload.single('imagem'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ erro: 'Nenhuma imagem enviada' });
        }

        const fileName = `${Date.now()}-${req.file.originalname}`;
        
        const { data, error } = await supabase.storage
            .from('produtos')
            .upload(fileName, req.file.buffer, {
                contentType: req.file.mimetype,
                upsert: false
            });

        if (error) throw error;

        // Pega URL pública
        const { data: { publicUrl } } = supabase.storage
            .from('produtos')
            .getPublicUrl(fileName);

        res.json({ url: publicUrl });
    } catch (error) {
        console.error('❌ ERRO UPLOAD:', error.message);
        res.status(500).json({ erro: 'Erro ao fazer upload' });
    }
});

// 3. Criar Produto
app.post('/api/admin/produtos', verificarAdmin, async (req, res) => {
    try {
        const { nome, preco, preco_antigo, imagem_url, categoria, estoque, descricao } = req.body;
        
        const result = await pool.query(
            'INSERT INTO produtos (nome, preco, preco_antigo, imagem_url, categoria, estoque, descricao) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [nome, preco, preco_antigo || null, imagem_url, categoria, estoque, descricao]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('❌ ERRO ADMIN CRIAR:', error.message);
        res.status(500).json({ erro: 'Erro ao criar produto' });
    }
});

// 4. Atualizar Produto
app.put('/api/admin/produtos/:id', verificarAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { nome, preco, preco_antigo, imagem_url, categoria, estoque, descricao } = req.body;

        const result = await pool.query(
            'UPDATE produtos SET nome=$1, preco=$2, preco_antigo=$3, imagem_url=$4, categoria=$5, estoque=$6, descricao=$7 WHERE id=$8 RETURNING *',
            [nome, preco, preco_antigo || null, imagem_url, categoria, estoque, descricao, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ erro: 'Produto não encontrado' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ ERRO ADMIN ATUALIZAR:', error.message);
        res.status(500).json({ erro: 'Erro ao atualizar produto' });
    }
});

// 5. Deletar Produto
app.delete('/api/admin/produtos/:id', verificarAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM produtos WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ erro: 'Produto não encontrado' });
        }
        res.json({ mensagem: 'Produto deletado com sucesso' });
    } catch (error) {
        console.error('❌ ERRO ADMIN DELETAR:', error.message);
        res.status(500).json({ erro: 'Erro ao deletar produto' });
    }
});

// ==================== PEDIDOS ====================

app.post('/api/pedidos', autenticarToken, async (req, res) => {
    try {
        const { carrinho, total } = req.body;
        const userId = req.usuario.id;

        const result = await pool.query(
            'INSERT INTO pedidos (usuario_id, itens, total, status) VALUES ($1, $2, $3, $4) RETURNING *',
            [userId, JSON.stringify(carrinho), total, 'pendente']
        );

        console.log('📦 Pedido criado:', result.rows[0].id);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('❌ ERRO AO CRIAR PEDIDO:', error.message);
        res.status(500).json({ erro: 'Erro ao criar pedido' });
    }
});

app.get('/api/meus-pedidos', autenticarToken, async (req, res) => {
    try {
        const userId = req.usuario.id;
        
        const result = await pool.query(
            'SELECT * FROM pedidos WHERE usuario_id = $1 ORDER BY created_at DESC',
            [userId]
        );

        res.json(result.rows);
    } catch (error) {
        console.error('❌ ERRO AO BUSCAR PEDIDOS:', error.message);
        res.status(500).json({ erro: 'Erro ao buscar pedidos' });
    }
});

// ==================== PAGAMENTO MERCADO PAGO ====================

app.post('/api/pagamento-multiplo', async (req, res) => {
    try {
        const { cart } = req.body;
        
        if (!cart || cart.length === 0) {
            return res.status(400).json({ erro: 'Carrinho vazio' });
        }

        const items = cart.map(item => ({
            title: item.nome,
            quantity: item.quantidade || 1,
            unit_price: Number(item.preco),
            currency_id: 'BRL'
        }));

        const body = {
            items: items,
            back_urls: {
                success: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/sucesso`,
                failure: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/falha`,
                pending: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/pendente`
            },
            auto_return: 'approved'
        };

        const preference = new Preference(client);
        const response = await preference.create({ body });
        
        console.log('✅ Pagamento gerado:', response.id);
        res.json({ 
            id: response.id,
            link: response.init_point
        });
    } catch (error) {
        console.error('❌ ERRO MP:', error.message);
        res.status(500).json({ 
            erro: 'Erro ao gerar pagamento',
            details: error.message
        });
    }
});

// ==================== INICIALIZAÇÃO ====================

app.listen(PORT, () => {
    console.log('🔥 Servidor DropSet ativo na porta', PORT);
    console.log('📡 Admin email: lucasteste@gmail.com');
    console.log('📦 Upload de imagens habilitado (Supabase Storage)');
});

module.exports = app;