defmodule Boruta.Openid.VerifiablePresentationsTest do
  alias Boruta.Openid.VerifiablePresentations
  use ExUnit.Case

  describe "validate_presentation/3" do
    setup do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" =>
            "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, expired_credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => 0
          },
          signer
        )

      {:ok, expired_vp_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
            "vp" => %{
              "verifiableCredential" => [expired_credential]
            }
          },
          signer
        )

      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      {:ok, vp_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
            "vp" => %{
              "verifiableCredential" => [credential]
            }
          },
          signer
        )

      {:ok, vp_token: vp_token, expired_vp_token: expired_vp_token}
    end

    test "returns an error when presentation submission is invalid", %{vp_token: vp_token} do
      presentation_submission = %{}

      presentation_definition = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
        "input_descriptors" => [
          %{
            "id" => "test",
            "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
            "constraints" => %{
              "fields" => [
                %{
                  "path" => ["$.vc.type"],
                  "filter" => %{
                    "type" => "array",
                    "contains" => %{"const" => "VerifiableAttestation"}
                  }
                }
              ]
            }
          }
        ]
      }

      assert VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) == {:error, "Required properties id, descriptor_map are missing at #."}
    end

    test "returns an error when signautre is invalid", %{expired_vp_token: vp_token} do
      presentation_submission = %{
        "id" => "test",
        "definition_id" => "test",
        "descriptor_map" => [
          %{
            "id" => "test",
            "format" => "jwt_vp",
            "path" => "$",
            "path_nested" => %{
              "id" => "test",
              "format" => "jwt_vc",
              "path" => "$.vp.verifiableCredential[0]"
            }
          }
        ]
      }

      presentation_definition = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
        "input_descriptors" => [
          %{
            "id" => "test",
            "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
            "constraints" => %{
              "fields" => [
                %{
                  "path" => ["$.vc.type"],
                  "filter" => %{
                    "type" => "array",
                    "contains" => %{"const" => "VerifiableAttestation"}
                  }
                }
              ]
            }
          }
        ]
      }

      assert VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) == {:error, "test is expired."}
    end

    test "returns ok", %{vp_token: vp_token} do
      presentation_submission = %{
        "id" => "test",
        "definition_id" => "test",
        "descriptor_map" => [
          %{
            "id" => "test",
            "format" => "jwt_vp",
            "path" => "$",
            "path_nested" => %{
              "id" => "test",
              "format" => "jwt_vc",
              "path" => "$.vp.verifiableCredential[0]"
            }
          }
        ]
      }

      presentation_definition = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
        "input_descriptors" => [
          %{
            "id" => "test",
            "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
            "constraints" => %{
              "fields" => [
                %{
                  "path" => ["$.vc.type"],
                  "filter" => %{
                    "type" => "array",
                    "contains" => %{"const" => "VerifiableAttestation"}
                  }
                },
                %{
                  "path" => ["$.vc.test"],
                  "filter" => %{
                    "type" => "string",
                    "pattern" => "ttern"
                  }
                }
              ]
            }
          }
        ]
      }

      assert VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) == :ok
    end
  end

  describe "validate_credential/3" do
    setup do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" =>
            "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, signer: signer}
    end

    test "returns an error with unknown format" do
      assert VerifiablePresentations.validate_credential("", %{}, "unknown") ==
               {:error, "format \"unknown\" is not supported"}
    end

    test "returns an error when descriptor is invalid", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{}

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "descriptor is invalid."}
    end

    test "returns an error when credential expired", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => 0,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => []
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "is expired."}
    end

    test "returns an error when not yet valid", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.type"],
              "filter" => %{
                "type" => "array",
                "contains" => %{"const" => "VerifiableAttestation"}
              }
            },
            %{
              "path" => ["$.vc.test"],
              "filter" => %{
                "type" => "string",
                "pattern" => "ttern"
              }
            }
          ]
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "is not yet valid."}
    end

    @tag :skip
    test "validates status", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern",
              "credentialStatus" => %{
                "statusListCredential" =>
                  "https://api-conformance.ebsi.eu/trusted-issuers-registry/v5/issuers/did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD/proxies/0x0090e5904a806f9228f88a502e4788d512288c9ba22106f16b5ae7b279ae3598/credentials/status/1",
                "statusListIndex" => "7"
              }
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.type"],
              "filter" => %{
                "type" => "array",
                "contains" => %{"const" => "VerifiableAttestation"}
              }
            },
            %{
              "path" => ["$.vc.test"],
              "filter" => %{
                "type" => "string",
                "pattern" => "ttern"
              }
            }
          ]
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "is revoked."}
    end

    test "validates contains constraint", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.type"],
              "filter" => %{
                "type" => "array",
                "contains" => %{"const" => "not present"}
              }
            }
          ]
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "descriptor test does not contains \"not present\"."}
    end

    test "validates pattern", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.test"],
              "filter" => %{
                "type" => "string",
                "pattern" => "non-existing"
              }
            }
          ]
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               {:error, "descriptor test does not contain pattern \"non-existing\"."}
    end

    test "is valid", %{signer: signer} do
      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
              "test" => "pattern"
            }
          },
          signer
        )

      descriptor = %{
        "id" => "test",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.type"],
              "filter" => %{
                "type" => "array",
                "contains" => %{"const" => "VerifiableAttestation"}
              }
            },
            %{
              "path" => ["$.vc.test"],
              "filter" => %{
                "type" => "string",
                "pattern" => "ttern"
              }
            }
          ]
        }
      }

      assert VerifiablePresentations.validate_credential(credential, descriptor, "jwt_vc") ==
               :ok
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
