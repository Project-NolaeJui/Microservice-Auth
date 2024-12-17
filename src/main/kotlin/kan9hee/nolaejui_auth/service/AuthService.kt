package kan9hee.nolaejui_auth.service

import kan9hee.nolaejui_auth.component.JwtTokenComponent
import kan9hee.nolaejui_auth.dao.BlacklistTokenRepository
import kan9hee.nolaejui_auth.dao.RefreshTokenRepository
import kan9hee.nolaejui_auth.dao.UserRepository
import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import kan9hee.nolaejui_auth.entity.BlacklistToken
import kan9hee.nolaejui_auth.entity.RefreshToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import kotlin.jvm.Throws

@Service
class AuthService(private val userRepository: UserRepository,
                  private val refreshTokenRepository: RefreshTokenRepository,
                  private val blacklistTokenRepository: BlacklistTokenRepository,
                  private val authenticationManagerBuilder: AuthenticationManagerBuilder,
                  private val jwtTokenComponent: JwtTokenComponent):UserDetailsService {

    @Transactional
    fun logIn(userID:String,password:String): JwtTokenDTO {
        val authenticationToken = UsernamePasswordAuthenticationToken(userID, password)
        val authentication = authenticationManagerBuilder.`object`.authenticate(authenticationToken)

        val jwtToken = jwtTokenComponent.generateToken(authentication)
        refreshTokenRepository.save(RefreshToken(jwtToken.refreshToken,userID))

        return jwtToken
    }

    @Transactional
    fun logout(accessToken:String?,refreshTokenString:String){
        accessToken?.let {
            if(jwtTokenComponent.validateToken(it))
                blacklistTokenRepository.save(BlacklistToken(it))
        }
        blacklistTokenRepository.save(BlacklistToken(refreshTokenString))
        refreshTokenRepository.deleteById(refreshTokenString)
    }

    @Transactional
    fun reissueAccessToken(refreshTokenString:String): JwtTokenDTO {
        val refreshTokenInfo = refreshTokenRepository.findById(refreshTokenString)
            .orElseThrow { RuntimeException("Refresh token not found") }

        val user = loadUserByUsername(refreshTokenInfo.userID)
        val authentication = UsernamePasswordAuthenticationToken(user.username,user.password)

        blacklistTokenRepository.save(BlacklistToken(refreshTokenString))
        refreshTokenRepository.deleteById(refreshTokenString)

        val newAccessToken = jwtTokenComponent.generateToken(authentication)
        refreshTokenRepository.save(RefreshToken(newAccessToken.refreshToken,user.username))

        return newAccessToken
    }

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(userID: String): UserDetails {
        val user = userRepository.findUsername(userID)
        return User(user.username,user.password,user.authorities)
    }
}