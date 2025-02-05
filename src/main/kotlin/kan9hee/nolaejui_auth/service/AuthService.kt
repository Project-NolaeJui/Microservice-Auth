package kan9hee.nolaejui_auth.service

import kan9hee.nolaejui_auth.component.JwtTokenComponent
import kan9hee.nolaejui_auth.config.PasswordEncoderConfig
import kan9hee.nolaejui_auth.dao.BlacklistTokenRepository
import kan9hee.nolaejui_auth.dao.RefreshTokenRepository
import kan9hee.nolaejui_auth.dao.UserRepository
import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import kan9hee.nolaejui_auth.dto.LogOutDTO
import kan9hee.nolaejui_auth.dto.UserCredentialsDTO
import kan9hee.nolaejui_auth.entity.BlacklistToken
import kan9hee.nolaejui_auth.entity.RefreshToken
import kan9hee.nolaejui_auth.entity.UserData
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
class AuthService(private val passwordEncoderConfig: PasswordEncoderConfig,
                  private val externalService: ExternalService,
                  private val userRepository: UserRepository,
                  private val refreshTokenRepository: RefreshTokenRepository,
                  private val blacklistTokenRepository: BlacklistTokenRepository,
                  private val authenticationManagerBuilder: AuthenticationManagerBuilder,
                  private val jwtTokenComponent: JwtTokenComponent):UserDetailsService {

    @Transactional
    suspend fun signUp(userCredentialsDTO: UserCredentialsDTO): Boolean {
        return try{
            val encodedPassword = encodePassword(userCredentialsDTO.insertedPassword)
            val newUser = UserData(
                userCredentialsDTO.insertedUserID,
                encodedPassword,
                "User"
            )

            userRepository.save(newUser)
            externalService.createAndDeletePlaylistForUser(userCredentialsDTO.insertedUserID,true)
            true
        } catch (e:Exception) {
            false
        }
    }

    @Transactional
    suspend fun signOut(logOutDTO: LogOutDTO): Boolean {
        return try{
            val refreshTokenInfo = validateUserCredentials(logOutDTO.refreshToken)
            logOut(logOutDTO)
            val userName = logOutDTO.accessToken?.let { jwtTokenComponent.getUsernameFrom(it) }
            userName?.let { externalService.createAndDeletePlaylistForUser(it,false) }
            userRepository.deleteByUserID(refreshTokenInfo.userID)
            true
        } catch (e:Exception) {
            false
        }
    }

    @Transactional
    fun logIn(userCredentialsDTO: UserCredentialsDTO): JwtTokenDTO {
        val user = loadUserByUsername(userCredentialsDTO.insertedUserID)
        val encodedPassword = encodePassword(userCredentialsDTO.insertedPassword)
        if (user.password != encodedPassword) {
            throw RuntimeException("Password mismatch")
        }

        val authenticationToken = UsernamePasswordAuthenticationToken(
            userCredentialsDTO.insertedUserID,
            userCredentialsDTO.insertedPassword
        )
        val authentication = authenticationManagerBuilder.`object`.authenticate(authenticationToken)

        val jwtToken = jwtTokenComponent.generateToken(authentication)
        refreshTokenRepository.save(
            RefreshToken(jwtToken.refreshToken, userCredentialsDTO.insertedUserID)
        )

        return jwtToken
    }

    @Transactional
    fun logInByToken(jwtTokenDTO: JwtTokenDTO): JwtTokenDTO {
        val isAccessTokenActive = jwtTokenComponent.validateToken(jwtTokenDTO.accessToken)

        if(isAccessTokenActive) {
            return jwtTokenDTO
        }
        else{
            val isRefreshTokenActive = jwtTokenComponent.validateToken(jwtTokenDTO.refreshToken)
            if(!isRefreshTokenActive)
                throw IllegalArgumentException("유효하지 않은 토큰입니다.")

            val newJwtTokenDTO = reissueAccessToken(jwtTokenDTO.refreshToken)
            return newJwtTokenDTO
        }
    }

    @Transactional
    fun logOut(logOutDTO: LogOutDTO) {
        logOutDTO.accessToken?.takeIf { jwtTokenComponent.validateToken(it) }?.let {
            blacklistTokenRepository.save(BlacklistToken(it))
        }

        blacklistTokenRepository.save(BlacklistToken(logOutDTO.refreshToken))
        refreshTokenRepository.deleteById(logOutDTO.refreshToken)
    }

    @Transactional
    fun reissueAccessToken(refreshTokenString: String): JwtTokenDTO {
        val refreshTokenInfo = validateUserCredentials(refreshTokenString)

        val user = loadUserByUsername(refreshTokenInfo.userID)
        val authentication = UsernamePasswordAuthenticationToken(user.username, user.password)

        blacklistTokenRepository.save(BlacklistToken(refreshTokenString))
        refreshTokenRepository.deleteById(refreshTokenString)

        val newAccessToken = jwtTokenComponent.generateToken(authentication)
        refreshTokenRepository.save(
            RefreshToken(newAccessToken.refreshToken, user.username)
        )

        return newAccessToken
    }

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(userID: String): UserDetails {
        return userRepository.findByUserID(userID)?.let {
            User(it.username, it.password, it.authorities)
        } ?: throw RuntimeException("User not found with ID: $userID")
    }

    private fun encodePassword(password: String): String {
        return passwordEncoderConfig.passwordEncoder().encode(password)
    }

    private fun validateUserCredentials(refreshTokenString: String): RefreshToken {
        return refreshTokenRepository.findById(refreshTokenString)
            .orElseThrow { RuntimeException("Refresh token not found") }
    }
}