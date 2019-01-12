<?php

//Headers
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers, Content-Type, Access-Control-Allow-Methods, Authorization, X-Requested-With');

include_once '../../config/Database.php';
include_once '../../models/User.php';
include_once '../../config/Access.php';
    
//Get raw posted data
$data = json_decode(file_get_contents("php://input"));

//Validando o token de acesso recebido
if (Access::compare_token($data->token)) {

    //Instantiate DB & Connect
    $database = new Database();
    $db = $database->connect();
    
    //Instantiate User object
    $user = new User($db);

    $user->nome = $data->nome;
    $user->email = $data->email;
    $user->senha = $data->senha;

    echo (json_encode($user->create()));
} else {
    echo (json_encode(array("sucesso" => false, "mensagem" => "Acesso a API negado.")));
}

