package kan9hee.nolaejui_auth.service

import org.springframework.stereotype.Service
import MusicListServerGrpcKt
import net.devh.boot.grpc.client.inject.GrpcClient

@Service
class ExternalService(@GrpcClient("nolaejui-playlist")
                      private val playlistStub:MusicListServerGrpcKt.MusicListServerCoroutineStub) {

    suspend fun createDefaultPickupPlaylist(userName:String){
        val request = Auth.UserName.newBuilder()
            .setUserName(userName)
            .build()

        val response = playlistStub.createDefaultPickupPlaylist(request)
        if(!response.isSuccess)
            throw RuntimeException(response.resultMessage)
    }

    suspend fun deleteUsersAllPlaylist(userName:String){
        val request = Auth.UserName.newBuilder()
            .setUserName(userName)
            .build()

        val response = playlistStub.deleteUsersAllPlaylist(request)
        if(!response.isSuccess)
            throw RuntimeException(response.resultMessage)
    }
}