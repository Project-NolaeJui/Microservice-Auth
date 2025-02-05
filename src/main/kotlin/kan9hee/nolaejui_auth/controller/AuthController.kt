package kan9hee.nolaejui_auth.controller

import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import kan9hee.nolaejui_auth.dto.LogOutDTO
import kan9hee.nolaejui_auth.dto.UserCredentialsDTO
import kan9hee.nolaejui_auth.service.AuthService
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class AuthController(private val authService: AuthService) {

    @PostMapping("/signUp")
    suspend fun signUp(@RequestBody userCredentialsDTO: UserCredentialsDTO): Boolean {
        return authService.signUp(userCredentialsDTO)
    }

    @PostMapping("/signOut")
    fun signOut(@RequestBody logOutDTO: LogOutDTO) {
        authService.logOut(logOutDTO)
    }

    @PostMapping("/logIn")
    fun logIn(@RequestBody userCredentialsDTO: UserCredentialsDTO): JwtTokenDTO {
        return authService.logIn(userCredentialsDTO)
    }

    @PostMapping("/logInByToken")
    fun logInByToken(@RequestBody jwtTokenDTO: JwtTokenDTO): JwtTokenDTO {
        return authService.logInByToken(jwtTokenDTO)
    }

    @PostMapping("/logOut")
    suspend fun logOut(@RequestBody logOutDTO: LogOutDTO) {
        authService.signOut(logOutDTO)
    }

    @PostMapping("/reissueAccessToken")
    fun reissueAccessToken(@RequestBody refreshTokenString:String): JwtTokenDTO {
        return authService.reissueAccessToken(refreshTokenString)
    }
}