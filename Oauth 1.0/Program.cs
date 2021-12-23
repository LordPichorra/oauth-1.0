// See https://aka.ms/new-console-template for more information

using Oauth_1._0;

var pcks8 = @"-----BEGIN PRIVATE KEY-----
                                MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPCUEj/SCNALB941
                                I9amYqDdvkWhdpTRURY8jPLcRHg/MueoBExb25nuQ/NLmH2xmrFCq7JYt4IshdYs
                                Suj5YZSG+adgTm1YFua2Pf2nkJzAGoRBtKl/rvJvY7nVCNZMdXEDfw2TTLIY8LPA
                                iahVNOxvcZlnuRat5ADAyoaYKhy5AgMBAAECgYBQMaubppHVd7fZtHEL3k7GPORu
                                JZJ3rQaQmQKK+i3Av6BiZDl6kqwzNZ9k/HAKhieAqy68tqIFPH4olH8sBeUmjhX6
                                rccvrO2FXbpi7IeUKmZ9Bw9p3JCCV9Pe2WdoNLosYZ7uYsWv/17FUhVER1MtcW35
                                0Hv8530mGoMl5jjy4QJBAPxwAq5WT8PPUJkwv8I2SOBD1AEduijthkbAxrySF7Oa
                                rJL49xJ+hW+yuQpINDnMqwE3Lg+0ulU/Ag58oJYn090CQQDz+TeHjNoOdwrcZH1C
                                HBhGXezpeErQG1y7vyjYOHpA/FDaC1NxOBOGQ/KXwe4ErhCUydx9wKi1nhv5F5cy
                                g1yNAkEA2si5ih+EQlELqbl2ePxTbQtcUxtQnOg/2FJ77DMyF5eWukrM2FqPi596
                                gE7T9MRN8V/BrBsW44sYXTXmeD1MgQJAM1yjERlZCrSLB8zsBc/uWFoLtzcI4Pjx
                                s+DRk3uIWUgFKXI69dntWlXRq5s7JacTfI9mqN63ZczMbMtHnG3FPQJBANFYpVmW
                                xWybzXZ+GYib0wJiNRETWL1pIvluUX5RAXG2zKm8NM2qIk3eRpoPsROFweHwqztt
                                NO/wG9VJQ75frfQ=
                                -----END PRIVATE KEY-----
                                ";
var url = "http://10.240.78.201:8081/rest/api/latest/issuetype";
var token = "PxDTWvgbeuQSV77WjFxyu0RmvkyR1cLJ";
var consumerKey = "OauthKey";

var oauth1Old = new Oauth1Old(privateKeyContent: pcks8, url: url, consumerKey: consumerKey, token: token);

var response = oauth1Old.RequestOath1();

Console.WriteLine(response);

