<?php

include_once '../../models/Bcrypt.php';

class User
{
    //Banco de Dados
    private $conn;
    private $table = 'usuarios';

    //Propriedades do Usuário
    public $id;
    public $nome;
    public $email;
    public $senha;
    public $ativo;

    //Construtor com banco de dados
    public function __construct($db)
    {
        $this->conn = $db;
    }

    //Adiciona Usuário
    public function create()
    {

        $erros = array();

        $query = 'INSERT INTO ' . $this->table . ' SET nome = :nome, email = :email, senha = :senha, ativo = :ativo';
          
        //Prepare Statement
        $stmt = $this->conn->prepare($query);
          
          
        //Clean data
        $this->nome = htmlspecialchars(strip_tags($this->nome));
        $this->email = htmlspecialchars(strip_tags($this->email));
        $this->senha = htmlspecialchars(strip_tags($this->senha));

        //Validando e-mail
        if (empty($this->email)) {
            //se o e-mail não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo e-mail está vazio."
            ));
        } else if (!$this->validar_email()) {
            //se o e-mail não for válido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O formato do e-mail é inválido."
            ));
        } else if ($this->email_cadastrado()) {
            //valida se o email está cadastrado
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O e-mail informado já está cadastrado."
            ));
        }


        //Validando Senha
        if (empty($this->senha)) {
            //se a senha não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo senha está vazio."
            ));
        } else {
            //Se estiver preenchida verifica o número de caracteres para ser ao menos de 6
            if (strlen($this->senha) < 6) {
                array_push($erros, array(
                    "sucesso" => false,
                    "mensagem" => "O campo senha deve conter no mínimo 6 caracteres."
                ));
            } else {
                //Criptografando a senha
                $hash = Bcrypt::hash($this->senha);
            }
        }


         //Validando Nome
        if (empty($this->nome)) {
            //se a senha não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo nome está vazio."
            ));
        }

        if (empty($erros)) {

            $retorno = array();

            //Se nenhum erro foi encontrado

            //Usuário é criado e ativado
            $ativo = "true";

            //BIND PARAMS
            $stmt->bindParam(':nome', $this->nome);
            $stmt->bindParam(':email', $this->email);
            $stmt->bindParam(':senha', $hash);
            $stmt->bindParam(':ativo', $ativo);
            
            //Execute Query
            if ($stmt->execute()) {
                array_push($retorno, array(
                    "sucesso" => true,
                    "mensagem" => "Usuário criado com sucesso."
                ));
            } else {
                //ERROR MSG
                printf("ERROR: %s.\n", $stmt->error);
                array_push($retorno, array(
                    "sucesso" => false,
                    "mensagem" => "Falha ao criar usuário."
                ));

            }
            return $retorno;
        } else {
            //se foram encontrados erros
            return $erros;
        }
    }


    //Faz Login
    public function login()
    {

        $erros = array();

        //Validando e-mail
        if (empty($this->email)) {
                //se o e-mail não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo e-mail está vazio."
            ));
        } else if (!$this->validar_email()) {
        //se o e-mail não for válido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O formato do e-mail é inválido."
            ));
        } 
    
    
        //Validando Senha
        if (empty($this->senha)) {
            //se a senha não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo senha está vazio."
            ));
        } 
        // else {
        //     //Se estiver preenchida verifica o número de caracteres para ser ao menos de 6
        //     if (strlen($this->senha) < 6) {
        //         array_push($erros, array(
        //             "sucesso" => false,
        //             "mensagem" => "O campo senha deve conter no mínimo 6 caracteres."
        //         ));
        //     }
        // }

        if (empty($erros)) {
            $retorno = array();
            //Se nenhum erro foi encontrado
            //Busca usuário por email
            $result = $this->get_by_email($this->email);

            $row = $result->fetch(PDO::FETCH_ASSOC);

            $num = $result->rowCount();

            if ($num > 0) {
                $senha_bd = $row["senha"];

                if (Bcrypt::check($this->senha, $senha_bd)) {
                    array_push($retorno, array(
                        "sucesso" => true,
                        "mensagem" => "Login efetuado com sucesso.",
                        "id" => $row["id"],
                        "nome" => $row["nome"],
                        "email" => $row["email"]
                    ));
                } else {
                    array_push($retorno, array(
                        "sucesso" => false,
                        "mensagem" => "E-mail e/ou senha incorreto(s)."
                    ));
                }

            } else {
                array_push($retorno, array(
                    "sucesso" => false,
                    "mensagem" => "E-mail e/ou senha incorreto(s)."
                ));
            }
            return $retorno;
        } else {
            //se foram encontrados erros
            return $erros;
        }
    }

    //Desabilita usuário
    public function disable()
    {

        $erros = array();
    
        //Validando e-mail
        if (empty($this->id)) {
            //se o e-mail não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O id e-mail está vazio."
            ));
        }
        
        
        //Validando Senha
        if (empty($this->senha)) {
                //se a senha não está preenchido
            array_push($erros, array(
                "sucesso" => false,
                "mensagem" => "O campo senha está vazio."
            ));
        } 

        if (empty($erros)) {
            $retorno = array();
            //Se nenhum erro foi encontrado
            //Busca usuário por email
            $result = $this->get_by_id($this->id);

            $row = $result->fetch(PDO::FETCH_ASSOC);

            $num = $result->rowCount();

            if ($num > 0) {
                $senha_bd = $row["senha"];

                if (Bcrypt::check($this->senha, $senha_bd)) {
                //fazer a atualização aqui



                    $query = 'UPDATE ' . $this->table . ' SET ativo = "false" WHERE id = :id;';
        
                     //Prepare Statement
                    $stmt = $this->conn->prepare($query);
                
                
                    //Clean data
                    $this->prod = htmlspecialchars(strip_tags($this->id));

                
        
                    //BIND PARAM
                    $stmt->bindParam(':id', $this->id);
        
                      //Execute Query
                    if ($stmt->execute()) {
                        array_push($retorno, array(
                            "sucesso" => true,
                            "mensagem" => "Usuário desativado com sucesso."
                        ));
                    } else {
                        //ERROR MSG
                        printf("ERROR: %s.\n", $stmt->error);
                        array_push($retorno, array(
                            "sucesso" => false,
                            "mensagem" => "Falha ao desativar usuário."
                        ));
                    }


                } else {
                    array_push($retorno, array(
                        "sucesso" => false,
                        "mensagem" => "Id e/ou senha incorreto(s)."
                    ));
                }

            } else {
                array_push($retorno, array(
                    "sucesso" => false,
                    "mensagem" => "Id e/ou senha incorreto(s)."
                ));
            }
            return $retorno;
        } else {
            //se foram encontrados erros
            return $erros;
        }
    }


    //valida o formato do email
    //true = e-mail válido
    public function validar_email()
    {
        if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        return true;
    }

    //verifica se o endereço de e-mail já está cadastrado
    //true = e-mail já cadastrado
    public function email_cadastrado()
    {
        //Get users on db
        $result = $this->get_by_email();

        //Get returned rows number
        $num = $result->rowCount();

        if ($num > 0) {
            return true;
        }

        return false;
    }

    //Get User by e-mail;
    public function get_by_email()
    {
        $query = 'SELECT * FROM ' . $this->table . ' WHERE email = ? AND ativo = "true"';

        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(1, $this->email);

        $stmt->execute();

        return $stmt;
    }

    //Get User by id;
    public function get_by_id()
    {
        $query = 'SELECT * FROM ' . $this->table . ' WHERE id = ? AND ativo = "true"';

        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(1, $this->id);

        $stmt->execute();

        return $stmt;
    }

}