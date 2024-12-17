package kan9hee.nolaejui_auth.controller

import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import kan9hee.nolaejui_auth.dto.LoginDTO
import kan9hee.nolaejui_auth.service.AuthService
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/Auth")
class AuthController(private val authService: AuthService) {

    @GetMapping("/login")
    fun login(@RequestBody loginDTO: LoginDTO): JwtTokenDTO {
        return authService.logIn(loginDTO.insertedUserID,loginDTO.insertedPassword)
    }

    @GetMapping("/logout")
    fun logout(@RequestHeader("Authorization") accessToken: String?,
               @RequestParam("refreshToken") refreshToken: String): JwtTokenDTO {
        return authService.logout(accessToken,refreshToken)
    }

    @GetMapping("/reissueAccessToken")
    fun reissueAccessToken(@RequestBody refreshTokenString:String): JwtTokenDTO {
        return authService.reissueAccessToken(refreshTokenString)
    }
}