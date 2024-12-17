package kan9hee.nolaejui_auth.dto

data class JwtTokenDTO(val grantType:String,
                       val accessToken:String,
                       val refreshToken:String)
