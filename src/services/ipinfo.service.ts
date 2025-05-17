import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

interface IPInfoResponse {
  ip: string;
  asn?: string;
  as_name?: string;
  as_domain?: string;
  country_code: string;
  country: string;
  continent_code?: string;
  continent?: string;
}

export class IPInfoService {
  private static apiKey = process.env.IPINFO_API_KEY;

  /**
   * Obtém informações detalhadas sobre um endereço IP, incluindo país
   * @param ip O endereço IP para consulta
   * @returns Detalhes do IP, incluindo país
   */
  static async getIPInfo(ip: string): Promise<IPInfoResponse | null> {
    try {
      if (!this.apiKey) {
        console.error('IPINFO_API_KEY não definida no .env');
        return null;
      }

      const response = await axios.get<IPInfoResponse>(
        `https://api.ipinfo.io/lite/${ip}?token=${this.apiKey}`
      );

      console.log(`Obtidas informações de IP para: ${ip} - País: ${response.data.country}`);
      return response.data;
    } catch (error) {
      console.error('Erro ao obter informações do IP:', error);
      return null;
    }
  }

  /**
   * Obtém apenas o país a partir de um endereço IP
   * @param ip O endereço IP para consulta
   * @returns Nome do país ou "Desconhecido" em caso de erro
   */
  static async getCountryFromIP(ip: string): Promise<string> {
    try {
      const ipInfo = await this.getIPInfo(ip);
      if (ipInfo && ipInfo.country) {
        return ipInfo.country;
      }
      return 'Desconhecido';
    } catch (error) {
      console.error('Erro ao obter país do IP:', error);
      return 'Desconhecido';
    }
  }
} 