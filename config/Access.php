<?php

class Access
{
   //Token para validação de acesso
    private const TOKEN = "123456789";

    //Método que válida o acesso
    //Param $token = token recebido
    //true = acesso concedido
    public static function compare_token($token)
    {
        if (!empty($token)) {
            if (strcmp(self::TOKEN, $token) == 0) {
                return true;
            }
        }

        return false;
    }
}