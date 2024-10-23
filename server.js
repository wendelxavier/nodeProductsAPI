
// Criar o app, express...
const express = require("express");
const app = express();
const fs= require("fs"); //fire system, checa no servidor o arquivo e chia se der algum problema.

// Inicialização do banco de dados SQLite
const dbFile = "./.data/produtos2.db";
const exists = fs.existsSync(dbFile);
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(dbFile);

// 0.3.0: Chamando jwt, bcryptjs e body-parser
const jwt = require("jsonwebtoken");
const bcryptjs = require('bcryptjs');
const bodyParser = require('body-parser');

// Se o banco não existir, crie ele 1o
db.serialize(()=> {
  if (!exists) { // exists == false
    db.run("CREATE TABLE produtos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, preco REAL NOT NULL, estoque INTEGER NOT NULL DEFAULT 0)");
    console.log("Tabela PRODUTOS criada!");
  } else { //exists == True
    console.log("Tabela PRODUTOS já existe e funciona bem");
  }
});


// Vamos tratar quando o visitante acessar com o "/" (página principal)
app.get("/", function(request, response) {
  response.sendFile(__dirname + "/index.html");
  });

// Se não colçocar isso aqui, o POST não funciona...
app.use(express.json());

/*INICIO DO NOSSO API SERVER*/
// vamos criar um array de produros (futuramente será um banco de dados SQLite)
/*let produtos = [
  {id: 1,  nome: "iPhone 16", preco: 7799, estoque: 10},
  {id: 2, nome: "Samsung S24 Ultra", preco: 6626, estoque: 5}
]*/

// Serviço para criar tabela de usuários e 2 usuários
app.get("/criarUsuarios", function(request, response) {
  db.run("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL, tipo TEXT NOT NULL, UNIQUE(username))");
  db.run("INSERT INTO usuarios (username, password, tipo) VALUES ('fulano', '12345', 'user')");
  db.run("INSERT INTO usuarios (username, password, tipo) VALUES ('admin', 'admin123', 'admin')");
  return response.status(200).send();
});


const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, tipo: user.tipo }, 'seuSegredoJWT', { expiresIn: '1h' });
};

// Rota para login de usuário
app.post("/api/login", (request, response) => {
  const { username, password } = request.body;

  // Busca o usuário no banco de dados
  db.get(
    "SELECT id, username, password, tipo FROM usuarios WHERE username = ?",
    [username],
    (err, user) => {
      if (err) {
        return response.status(500).json({ error: "Erro no banco de dados." });
      }
      if (!user) {
        return response.status(404).json({ error: "Usuário não encontrado." });
      }

      //
      //aqui vai entrar criptografia depois..
      const passwordIsValid = bcryptjs.compareSync(password, user.password);
      if (passwordIsValid){
        const token = generateToken(user);
        return response.json({ message: "Login bem-sucedido!", token });
      } else {
        return response.status(401).json({ error: "Senha inválida." });
      }
    }
  );
});
  
// Verificar token!
const verifyToken = (request, response, next) => {
  const token = request.headers['x-access-token'];
  if (!token) { //undefined
    return response.status(403).json({error: 'Nenhum token foi fornecido.'});
  }
  
  jwt.verify(token, 'seuSegredoJWT', (error, decoded) => {
    if (error) {
      return response.status(500).json({error: 'Falha ao autenticar o token.'});
    }
    
    request.userid = decoded.id;
    request.usertipo = decoded.tipo;
    next();
  });
};

// Verificar token de ADMIN
const verifyAdminToken = (request, response, next) => { 
  const token = request.headers['x-access-token'];
  if (!token) { //undefined
    return response.status(403).json({error: 'Nenhum token foi fornecido.'});
  }
  
  jwt.verify(token, 'seuSegredoJWT', (error, decoded) => {
    if (error) {
      return response.status(500).json({error: 'Falha ao autenticar o token.'});
    }
    
    request.userid = decoded.id;
    request.usertipo = decoded.tipo;
    if (request.usertipo != 'admin'){
      return response.status(500).send({error: "Você não tem privilégios para apagar um produto."});
    } else {
      next();
    }
  });
};

// Rota GET para retornar todos os produtos
app.get("/api/produtos", verifyToken, function(request, response) {
  //response.json(produtos);
  db.all("SELECT  id, nome, preco, estoque FROM produtos", (error, linhas)=> {
    response.setHeader('content-type', 'text/json');
    return response.send(JSON.stringify(linhas));
  })
});

// Rota GET para retornar um único produto, passando o id do mesmo na URL
app.get("/api/produtos/:id", verifyToken, function(request, response) {
  const produto_id = parseInt(request.params.id);
  const sql = "SELECT id, nome, preco, estoque FROM produtos WHERE id = ?";
  db.get(sql, [produto_id], function(error, linha){
    if (error) {
      return response.status(500).send(error);
    } else {
      console.log(linha);
      if (!linha) {
        return response.status(404).send("Produto não encontrado.");
      } else {
        response.setHeader('content-type', 'application/json');
        return response.send(JSON.stringify(linha));
      }
    }
  });
  /*
  const produto = produtos.find(i => i.id === produto_id);
  
  if (!produto) { // produto == false
    return response.status(404).send("Produto não encontrado.");
  } else {
    return response.json(produto);
  }*/
});

// Rota POST para criar um produto...
app.post("/api/produtos", verifyAdminToken, function (request, response) {
  /*
  console.log(request.body);
  
  const novo_produto = {
    id: produtos.length + 1,
    nome: request.body.nome,
    preco: request.body.preco,
    estoque: request.body.estoque
  };
  
  produtos.push(novo_produto);
  response.status(201).json(novo_produto);
*/
  db.run("INSERT INTO produtos (nome, preco, estoque) VALUES (?, ?, ?)", request.body.nome, request.body.preco, request.body.estoque, function(error){
    if (error) {
      return response.status(500).send(error);
    } else {
      return response.status(201).json({ id: this.lastID, nome: request.body.nome, preco: request.body.preco, estoque: request.body.estoque});
    }
  });
});
// ROTA DO ATUALIZAR ...
app.patch("/api/produtos", function(request, response) {
  return response.status(500).send("Erro interno do servidor!");
});

// ATUALIZAR PRODUTO...
app.patch("/api/produtos/:id", verifyAdminToken, function(request, response) {
  const produto_id = parseInt(request.params.id);
  
  //Passando TUDO, nome, preco, estoque...
    // Passando TUDO, nome, preco, estoque..
  let set = "";
  let valores = [];
  
  // Se vai ter nome
  console.log(request.body.nome);
  if (request.body.nome != undefined){
    set = "nome=?";
    valores.push(request.body.nome);    
  }
  
  // Se vai ter preco
  if (request.body.preco != undefined){
    if (set.length > 0) {
      set += ",";
    }
    set += "preco=?";
    valores.push(request.body.preco);  
  }
  
  // Se vai ter estoque
  if (request.body.estoque != undefined){
    if (set.length > 0) {
      set += ",";
    }
    set += "estoque=?";
    valores.push(request.body.estoque);  
  }
  
  const sql = "UPDATE produtos SET "+set+" WHERE id=?";
  valores.push(produto_id);
  console.log(sql);
  
  db.run(sql, valores, function(error) {
    if (error) {
      return response.status(500).send("Erro interno do servidor.");
    } else {
      if (this.changes === 0) {
        return response.status(404).send("Produto não encontrado.");
      } else {
        return response.status(200).send();
      }
    }
  });
  /* try
  {
    const produto_id = parseInt(request.params.id);
    const produtoIndex = produtos.findIndex(i => i.id === produto_id);

    const produto_atualizado = {
      id: produto_id,
      nome: request.body.nome,
      preco: request.body.preco,
      estoque: request.body.estoque
    };

    if (produtoIndex === -1) {
      return response.status(404).send("Produto não encontrado.");
    } else {
      produtos[produtoIndex] = produto_atualizado;
      return response.status(200).send();
    }
  }
  catch(err) {
    return response.status(500).send("Erro interno do servidor!");
  }*/
});


// APAGAR PRODUTO CORRIGIDO.
app.delete("/api/produtos/:id", verifyAdminToken, function(request, response) {
  const produto_id = parseInt(request.params.id);
  
  const sql = "DELETE FROM produtos WHERE id=?";
  db.run(sql, produto_id, function(error){
    if (!error){
      return response.status(500).send("Erro no servidor.");
    } else {
      if (this.changes === 0) {
        return response.status(404).send("Produto não encontrado.");
      } else {
          return response.status(204).send();
      }
    }
  });
  /*const produtoIndex = produtos.findIndex(i => i.id === produto_id);

  //console.log(produtos);
  //console.log(produtoIndex);
  if (produtoIndex === -1) {
    return response.status(404).send("Produto não encontrado.");
  } else {
    produtos.splice(produtoIndex, 1);
    return response.status(204).send();
  }*/
});


/*FIM DO NOSSO API SERVER*/

// Endpoint/ROTA para cadastrar um novo usuário
app.post("/api/usuarios", verifyAdminToken, function (request, response) {
  const { username, password, tipo } = request.body;

  if (!username || !password || !tipo) {
    return response
      .status(500)
      .json({
        error:
          "Os parâmetros obrigatórios não foram passados corretamente no 'body'.",
      });
  }

  let sql = "";
  if (request.body.username != undefined) {
    sql = "SELECT id FROM usuarios WHERE username = ?";
    db.get(sql, username, function (error, linha) {
      if (error) {
        return response
          .status(500)
          .json({
            error: "Erro de banco de dados no cadastramento do usuário.",
          });
      }
      if (linha) {
        return response
          .status(400)
          .json({
            error:
              "Erro no cadastramento, já existe um usuário com este 'username'.",
          });
      }
    });
  }

  //Criptografar a senha
  const password_crypted = bcryptjs.hashSync(password, 8);
  //const password_crypted = password;

  sql = "INSERT INTO usuarios (username, password, tipo) VALUES (?, ?, ?)";
  db.run(sql, [username, password_crypted, tipo], function (error) {
    if (error) {
      return response.status(500).json({ error: "Erro ao cadastrar usuário." });
    } else {
      return response.json({ mensagem: "Usuário cadastrado com sucesso." });
    }
  });
});
//"Listener"
const listener = app.listen(process.env.PORT, function() {
  console.log("Your app is listening on port " + listener.address().port);
});