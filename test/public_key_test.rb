require 'test/unit'
require 'ssh_public_key'

class SSHPublicKeyTest < Test::Unit::TestCase
  RSAKEY = <<RSA
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVlYiHtFfcoME7krIar/caT5+CUqpLJd3yj4mT6AXAVGSKe/GmjQGax1xD33BlEGrdQ+G7km+grYMTOaz7OlPbq7HG4o66mN+RqWje1NOkOKRTSjR+HMy6GOJlo17lwekDFOz90c7F8rRYnwLc5Mt2H3Filzyu3nipVsXG6TFfoHUJo1v9UHy1y3f9yK9DCIcAPcuF1eN6kmnilfqTY3j8GlOaLOIkvEYE/yTXutcTV8oOybbbG+5XTGNPJckpCX0iKaZb1gQ30dhmzH4xXgatTbf3rEKs6mgbvIS/PNJjcU9hrWOwLcR+Jw5X59seEJDCkalKvRKkX2Tpi4onw6mw== jvoorhis@jvoorhis
RSA

  RSAKEY_E = 35
  RSAKEY_M = 24408050930543034452386051466409879414684067520374285355132796961550729899129155364455677362325669150754359670615102940636118877195794580288375112737903765406417456067918529441478974512856013752695538161076129916446792082695022285118897782926181788843870329152103326287034929518386586682765955587604566425854760108209605868926768563786723546070598260713182060944576006708526466255017829176199001772236324586516457885565540500685884542118915944069571482986612965710054757483168377567236174578824727328357759950476887210832906341740372630703544695151269012770162054529948633965153810896218465947323359740231748794727067

  DSAKEY = <<DSA
ssh-dss AAAAB3NzaC1kc3MAAACBAOxST6PN0e3Ry/4Ks7Dhqw7c0isgbXUSXcdi9vk+9HTWlk1zIcU31lcuED+A8ZPxEZ74G2nP23L1VGRYquvFIjSADnJSD7mVp8fak/Lxsrk9k/b8DEMKy+Y2hyzR1wqeAoCCJRkKHQOm3nginHsff14MHi/Y0yQdQQ4HD1jQycBBAAAAFQCWjSFdIbl3F5e4F5Mx6x7W5osUmwAAAIEArEe+Fg2Sa4xS0RieZ4OmmdtKl4zGcmKqjt80x0rBSpioZ7Q1Z99nJ6USYN9iTX6OYHAahXRN15QWES+N8A0XxsqwtbGdYYYhAkim3xWFlkHbMZGwbPfURN56E/hp6BYzP1VADmKQLR1HuJeMYgkZ457+vLS60UNg1dRkv+PomIIAAACAU2dHn1IK+n0vmJXRAYGPRRU8OY/fRXUFjsb/hkshfqNlnHVemPITJ/i4Kj1/EG9EgyG0IHiOnz4k0Ye3xPQWPJQo4jV77sYaqR4CS9Iqeh5HAakB8WLp4Jg2m9aFsGBr8z0oCHbMRPryq4hMVS+jvZXLtISdAxJSid3fVT2vuzA= jvoorhis@jvoorhis
DSA
  DSAKEY_P = 165950620304887594884135609168463435456975030032167489524497850318194612792761362778018433743240760339575503027641394260574970055390605825840800874395623852661763134421827522256823036810841966996496533797334568474233455519295649871982835925662246744416420207654868373530423342780942185276251990645140269678657 
  DSAKEY_Q = 859495927093092132489021088086156249337313301659
  DSAKEY_G = 120979301692404393273868117223565538404375798196259387100318771085866992172061990518837332418127252702458312741391664776201274497267406391122833354561436140439474680868904068235236089129980638892504547055285487884710265926302915559650739333104897349348589001086952911228829682594220717175440335338768026867842
  DSAKEY_Y = 58567884936005064871798078338950198157960353960239817665887577731752594469778397657411784034121541953043231563718348937388900185863651451122212554930418668265333665678558476629598005155001156340620679704050209200086098295350016791427054485372747467098906953590833533792856297022284628315267194401081344899888


  def test_algorithm
    key = SSHPublicKey.parse(RSAKEY)
    assert_equal 'RSA', key.algorithm
  end

  def test_parameters_rsa
    key = SSHPublicKey.parse(RSAKEY)
    assert_kind_of Hash, key.parameters
    e, m = key.parameters.values_at('e', 'm')
    assert_equal RSAKEY_E, e
    assert_equal RSAKEY_M, m
  end

  def test_algorithm_dsa
    key = SSHPublicKey.parse(DSAKEY)
    assert_equal 'DSA', key.algorithm
  end

  def test_parameters_dsa
    key = SSHPublicKey.parse(DSAKEY)
    assert_kind_of Hash, key.parameters
    p, q, g, y = key.parameters.values_at('p', 'q', 'g', 'y')
    assert_equal DSAKEY_P, p
    assert_equal DSAKEY_Q, q
    assert_equal DSAKEY_G, g
    assert_equal DSAKEY_Y, y
  end
end