package kan9hee.nolaejui_auth.entity

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Table(name = "user")
@Entity
class UserData(userID:String,
               encryptedPassword:String,
               systemLevel:String): UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private val id:Long=0

    @Column
    private val userID:String=userID

    @Column
    private val encryptedPassword:String=encryptedPassword

    @Column
    private val systemLevel:String=systemLevel

    override fun getAuthorities(): Collection<GrantedAuthority> =
        listOf(SimpleGrantedAuthority("ROLE_$systemLevel"))

    override fun getPassword(): String = encryptedPassword

    override fun getUsername(): String = userID
}