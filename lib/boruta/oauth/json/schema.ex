defmodule Boruta.Oauth.Json.Schema do
  @moduledoc false
  alias ExJsonSchema.Schema

  @uuid_pattern "\^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\$"

  def client_credentials do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{"type" => "string", "pattern" => "client_credentials"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "scope" => %{"type" => "string"}
      },
      "required" => ["grant_type", "client_id", "client_authentication"]
    }
    |> Schema.resolve()
  end

  def password do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{"type" => "string", "pattern" => "password"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "username" => %{"type" => "string"},
        "password" => %{"type" => "string"},
        "scope" => %{"type" => "string"}
      },
      "required" => ["grant_type", "client_id", "username", "password"]
    }
    |> Schema.resolve()
  end

  def authorization_code do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{"type" => "string", "pattern" => "authorization_code"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "code" => %{"type" => "string"},
        "redirect_uri" => %{"type" => "string"},
        "code_verifier" => %{"type" => "string"}
      },
      "required" => ["grant_type", "code", "client_id", "redirect_uri"]
    }
    |> Schema.resolve()
  end

  def preauthorization_code do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{"type" => "string", "pattern" => "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "pre-authorized_code" => %{"type" => "string"},
        "code_verifier" => %{"type" => "string"}
      },
      "required" => ["grant_type", "pre-authorized_code", "client_authentication"]
    }
    |> Schema.resolve()
  end

  def token do
    %{
      "type" => "object",
      "properties" => %{
        "response_type" => %{"type" => "string", "pattern" => "token"},
        "response_mode" => %{"type" => "string", "pattern" => "^(query|fragment)$"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "state" => %{"type" => "string"},
        "nonce" => %{"type" => "string"},
        "redirect_uri" => %{"type" => "string"},
        "prompt" => %{"type" => "string"}
      },
      "required" => ["response_type", "client_id", "redirect_uri"]
    }
    |> Schema.resolve()
  end

  def id_token do
    %{
      "type" => "object",
      "properties" => %{
        "response_type" => %{"type" => "string", "pattern" => "id_token"},
        "response_mode" => %{"type" => "string", "pattern" => "^(query|fragment)$"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "state" => %{"type" => "string"},
        "nonce" => %{"type" => "string"},
        "redirect_uri" => %{"type" => "string"}
      },
      "required" => ["response_type", "client_id", "redirect_uri"]
    }
    |> Schema.resolve()
  end

  def refresh_token do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{"type" => "string", "pattern" => "refresh_token"},
        "refresh_token" => %{"type" => "string"},
        "scope" => %{"type" => "string"}
      },
      "required" => ["grant_type", "refresh_token"]
    }
    |> Schema.resolve()
  end

  def preauthorized_code do
    %{
      "type" => "object",
      "properties" => %{
        "response_type" => %{"type" => "string", "pattern" => "urn:ietf:params:oauth:response-type:pre-authorized_code"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "state" => %{"type" => "string"},
        "nonce" => %{"type" => "string"},
        "redirect_uri" => %{"type" => "string"},
        "prompt" => %{"type" => "string"},
        "code_challenge" => %{"type" => "string"},
        "code_challenge_method" => %{
          "type" => "string",
          "pattern" => "plain|S256"
        }
      },
      "required" => ["response_type", "client_id", "redirect_uri"]
    }
    |> Schema.resolve()
  end

  def code do
    %{
      "type" => "object",
      "properties" => %{
        "response_type" => %{"type" => "string", "pattern" => "code"},
        "response_mode" => %{"type" => "string", "pattern" => "^(query|fragment)$"},
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "state" => %{"type" => "string"},
        "nonce" => %{"type" => "string"},
        "redirect_uri" => %{"type" => "string"},
        "prompt" => %{"type" => "string"},
        "code_challenge" => %{"type" => "string"},
        "code_challenge_method" => %{
          "type" => "string",
          "pattern" => "plain|S256"
        }
      },
      "required" => ["response_type", "client_id", "redirect_uri"]
    }
    |> Schema.resolve()
  end

  def introspect do
    %{
      "type" => "object",
      "properties" => %{
        "client_id" => %{
          "type" => "string",
          "pattern" => @uuid_pattern
        },
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "token" => %{"type" => "string"}
      },
      "required" => ["client_id", "client_authentication", "token"]
    }
    |> Schema.resolve()
  end

  def revoke do
    %{
      "type" => "object",
      "properties" => %{
        "client_id" => %{"type" => "string"},
        "client_authentication" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{"type" => "string", "pattern" => "^(basic|post|jwt)$"},
            "value" => %{"type" => ["string", "null"]}
          },
          "required" => ["type", "value"]
        },
        "token_type_hint" => %{"type" => "string", "pattern" => "^(access_token|refresh_token)$"},
        "token" => %{"type" => "string"}
      },
      "required" => ["client_id", "token"]
    }
    |> Schema.resolve()
  end

  def grant_type do
    %{
      "type" => "object",
      "properties" => %{
        "grant_type" => %{
          "type" => "string",
          "pattern" => "^(client_credentials|password|authorization_code|refresh_token)$"
        }
      },
      "required" => ["grant_type"]
    }
    |> Schema.resolve()
  end
end
