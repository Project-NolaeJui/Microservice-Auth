package kan9hee.nolaejui_auth.controller

import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import kan9hee.nolaejui_auth.dto.LogOutDTO
import kan9hee.nolaejui_auth.dto.UserCredentialsDTO
import kan9hee.nolaejui_auth.service.AuthService
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/Auth")
class AuthController(private val authService: AuthService) {

    @PostMapping("/signUp")
    fun signUp(@RequestBody userCredentialsDTO: UserCredentialsDTO): JwtTokenDTO {
        return authService.logIn(userCredentialsDTO)
    }

    @PostMapping("/signOut")
    fun signOut(@RequestBody logOutDTO: LogOutDTO) {
        authService.logOut(logOutDTO)
    }

    @PostMapping("/logIn")
    fun logIn(@RequestBody userCredentialsDTO: UserCredentialsDTO): JwtTokenDTO {
        return authService.logIn(userCredentialsDTO)
    }

    @PostMapping("/logOut")
    fun logOut(@RequestBody logOutDTO: LogOutDTO) {
        authService.logOut(logOutDTO)
    }

    @PostMapping("/reissueAccessToken")
    fun reissueAccessToken(@RequestBody refreshTokenString:String): JwtTokenDTO {
        return authService.reissueAccessToken(refreshTokenString)
    }
}