namespace API.Dtos
{
    public class AuthResponseDto
    {
        public string? Token { get; set; }

        public bool IsSuccess { get; set; }

        public string? Message { get; set; }
    }
}
